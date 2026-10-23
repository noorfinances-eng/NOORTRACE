# CT-6 — Vérificateur

Version 0.1, 2026-10-22. Spécification normative, soumise à la revue de la
porte 1 du plan de projet (document interne). Elle met en œuvre l'étape
« Vérification » de la chaîne de traitement et la section « Dossier et
vérification » de l'[architecture cible](../ARCHITECTURE.md). Elle vérifie le
dossier v0 de [CT-1](CT-1-evenements-et-formats.md) §11 sans en changer la
forme, et ce que l'enregistreur de [CT-2](CT-2-enregistreur.md) produit. Elle
ne clôt aucune décision ouverte de l'architecture ; elle a changé un choix
qui y était écrit : les trois ancres portent sur `periodHash`, et non sur la
seule racine (section 16).

La spécification a deux parties. La **partie A** (sections 0 à 8) dit ce que
le vérificateur croit, ce qu'il lit, ce qu'il exécute et ce qu'il affirme ; un
réviseur peut s'y arrêter. La **partie B** (sections 9 à 17 et annexe A) dit
comment les contrôles 4, 5 et 8 se calculent, ce que contient le fichier
d'ancres, ce que CT-4 et CT-5 doivent produire, comment le binaire se
construit, et comment les vecteurs sont disposés. L'annexe B donne, pour
chaque renvoi aux notes de recherche, les sources primaires publiques.

## 0. En-tête et conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1 et CT-2.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (EX-6.4 :
quatrième règle de la section 6), stable, auquel le plan de tests (CT-9)
attache ses tests. Les identifiants sont numérotés dans l'ordre du texte à
l'intérieur de chaque section de premier niveau, sous-sections comprises. Une
règle ajoutée par une révision reçoit le numéro qui suit le plus grand de sa
section ; aucun numéro n'est réattribué ; une règle retirée garde son numéro,
marqué « retiré ». En version 0.1, EX-6.15, EX-9.21, EX-13.12 et EX-13.13 ont
été ajoutées par une révision, après la numérotation initiale de leur
section. Elles gardent leur numéro (règle ci-dessus) et ne sont donc pas à
leur rang dans le texte.

Les vérifications élémentaires portent l'identifiant de leur famille :

| Famille | Contrôle servi | Définie par |
|---|---|---|
| D-, E-, C-, M-, P-, A- | index du dossier, contrôles 1, 2, 3, 6, 7 | CT-1 §11.4, reprises sans changement |
| T- | 4, jeton RFC 3161 | section 9 |
| O- | 5, preuve OpenTimestamps | section 10 |
| R- | 8, registre et certificat de commit | section 11 |
| N- | fichier d'ancres et son application au dossier | section 12 |
| V- | verdict, énoncé et codes de retour | section 6.9 |

Les clés JSON sont en anglais ; les valeurs énumérées sont en français, sans
accent (`reussi`, `echoue`, `non_execute`, `ancre_absente`), comme dans CT-1.
Les encodages sont ceux de CT-1 §3 ; les instants que le vérificateur écrit
suivent EX-6.11.

« Le vérificateur » désigne toute implémentation conforme : l'implémentation
de référence JavaScript `scripts/verify/dossier.mjs` et le binaire Go de la
section 14. Elles ont la même interface (section 8) et rendent, sur les mêmes
entrées, les mêmes statuts, le même verdict et le même énoncé. C'est
l'exigence que toute implémentation conforme remplit. Le binaire n'est livré
qu'en phase 2 (section 1) ; en version 0, la seule implémentation conforme
livrée est l'implémentation de référence.

Les faits externes (normes d'horodatage, format OpenTimestamps, règles de
Bitcoin, code de noorcore, chaîne d'outils Go) viennent de quatre notes de
recherche du lot CT-6 (les « digests » R1 à R4), internes et non publiées,
relues le 2026-10-22 sur les sources primaires qu'elles citent. Chaque fait
porte un renvoi court : la note suivie du numéro du fait (« R1 F3.16 »,
« R2-F37 », « R3 NV7 » pour un point non vérifié de la note) ou d'une de ses
conséquences pour la conception (« R3, conséquence 6 »), un point non vérifié
numéroté de la note (« point non vérifié 5 du digest R2 »), ou la note seule
quand le passage renvoie à la note entière. L'annexe B donne, pour chaque
renvoi, l'objet du fait, les sources primaires publiques consultées et leur
date, ou signale que la note n'en cite aucune ; certaines de ces sources
figurent aussi dans le texte. Un fait tiré du code de noorcore, dépôt privé,
n'est pas recoupable publiquement. Ce qui n'a pas pu être vérifié est écrit
« non vérifié ».

Lecture : un réviseur qui ne lit qu'une section lit la section 7.

## 1. Objet, périmètre et relations

CT-6 fixe, pour la version 0 du vérificateur :

1. ce qu'il croit et ne croit pas, et contre quels adversaires (section 3) ;
2. ses entrées : le dossier v0, trois entrées facultatives, le fichier
   d'ancres du réviseur, et leurs limites (section 4) ;
3. les huit contrôles de l'architecture, les vérifications qui les composent,
   leur ordre et leurs dépendances (section 5) ;
4. les statuts, les raisons de non-exécution, le verdict global, l'énoncé en
   une phrase et la compatibilité avec les dossiers de CT-1 (section 6) ;
5. ce que chaque verdict et chaque contrôle prouvent et ne prouvent pas
   (section 7) ;
6. la ligne de commande, les codes de retour et les deux sorties, lisible et
   JSON (section 8) ;
7. les contrôles 4, 5 et 8 (sections 9 à 11), le fichier d'ancres
   (section 12), ce que CT-4 et CT-5 doivent produire (section 13), le
   binaire (section 14), la sûreté du vérificateur (section 15), les décisions
   de l'architecture touchées (section 16), ce que la version ne couvre pas
   (section 17), les vecteurs (annexe A) et les sources des faits externes
   (annexe B).

Hors périmètre : la production des cinq parties réservées du dossier (CT-4
pour le registre, CT-5 pour l'horodatage et OpenTimestamps ; la section 13 dit
ce qu'elles doivent livrer) ; l'export du dossier ; la décision qu'une
autorité d'horodatage est qualifiée, que le vérificateur reprend telle que le
réviseur la déclare (section 12) ; toute consultation d'un nœud Bitcoin ou d'un
nœud du registre ; les preuves d'état du registre (appartenance d'une adresse
au `CuratorSet`, non-révocation d'une clé), que noorcore ne sert pas
(`eth_getProof` absent, état historique servi sans preuve, R3 F30, F41).

Ce que la version 0 livre :

| Élément | Livré |
|---|---|
| Cette spécification ; les schémas `ancres-confiance-v0`, `rapport-verification-v0`, `entetes-bitcoin-v0`, `registre-v0` et `validateurs-v0` | avec CT-6 |
| L'implémentation de référence JavaScript des huit contrôles, dans `scripts/verify/dossier.mjs` (option `--ancres`) | avec CT-6 |
| Les vecteurs `spec/vecteurs/ct-6`, leurs tests et l'intégration continue | avec CT-6 |
| Le binaire Go, sa construction reproductible et sa diffusion | phase 2 du plan (section 14) |

Relations avec les autres spécifications :

| Spécification | Ce que CT-6 en reprend | Ce que CT-6 lui fournit ou lui impose |
|---|---|---|
| CT-1 | Le dossier v0 et ses douze parties (§11.1, §11.2) ; les vingt-huit vérifications D-1 à A-4 (§11.4) ; `periodHash` (§10.2) ; `anchorFingerprint` (§10.4) ; la borne du verdict (§11.3) | Le statut de chacun des huit contrôles, le verdict, l'énoncé. Aucune vérification de CT-1 n'est redéfinie. Les lignes de §11.2 des cinq parties réservées renvoient à CT-6, et celles de `jeton-rfc3161.der` et `preuve.ots` disent `periodHash` (section 16). |
| CT-2 | La clé Ed25519 de l'enregistreur et la clé de chaîne secp256k1 sous laquelle elle est inscrite, qui signe les ancres et relaie les clôtures (§11, EX-11.13, EX-11.19) ; ce que la capture ne couvre pas (§21) | Rien de nouveau : le vérificateur contrôle ce que l'enregistreur produit. |
| CT-4 | — | Le contenu de `registre.json`, `certificat-commit.json` et `validateurs.json`, et leur capture au moment de chaque transaction (sections 11 et 13). |
| CT-5 | — | Le contenu de `jeton-rfc3161.der` et de `preuve.ots`, et le fichier d'en-têtes Bitcoin qui accompagne le dossier (sections 9, 10 et 13). |
| CT-9 | — | Les identifiants EX-, T-, O-, R-, N- et V-, et les vecteurs `spec/vecteurs/ct-6` (annexe A). |

## 2. Terminologie

Les termes de CT-1 §2 (journal, événement, pièce, référence, période,
manifeste, racine, chemin d'audit, dossier, approbateur, JCS) et ceux de
CT-2 §2 (enregistreur, signataire, clé de chaîne) gardent leur sens. S'y
ajoutent :

| Terme | Définition |
|---|---|
| Vérificateur | Programme hors ligne qui lit un dossier et rend un verdict (section 0). |
| Réviseur | La personne qui vérifie : auditeur, régulateur, juge, client. Il choisit ses ancres de confiance et lit l'énoncé. |
| Exportateur | Celui qui assemble le dossier et ses entrées à part, en pratique le client, avec l'enregistreur (CT-2) et les outils de CT-4 et CT-5. Le vérificateur ne le croit pas. |
| Ancre de confiance | Donnée que le vérificateur tient pour vraie sans la vérifier : certificat d'une autorité d'horodatage, point de contrôle Bitcoin, identifiant de chaîne, adresse de contrat et jeu de validateurs du registre, clé publique d'enregistreur. |
| Fichier d'ancres | Le fichier JSON où le réviseur écrit ses ancres de confiance (schéma `ancres-confiance-v0`, section 12). |
| Déclaratif | Se dit d'une valeur qui vient du dossier ou d'une entrée à part : le vérificateur la contrôle par calcul, il ne la croit pas. |
| De confiance | Se dit d'une valeur qui vient du fichier d'ancres. |
| Contrôle | L'un des huit contrôles numérotés de l'architecture, de 1 à 8. |
| Vérification | Règle élémentaire identifiée (E-7, T-2, R-5…), qui sert un ou deux contrôles. |
| Statut | Résultat d'une vérification ou d'un contrôle : `reussi`, `echoue` ou `non_execute`. |
| Raison | Motif d'un statut `non_execute`, pris dans la liste fermée de la section 6.2. |
| Raison admise | Raison qui n'empêche pas un verdict `valide`. |
| Verdict | `valide`, `invalide` ou `incomplet` (section 6.4), ou aucun verdict quand l'entrée est inutilisable (code 2). |
| Énoncé | Phrase, en français et en anglais, qui dit ce que le verdict établit et ce qu'il n'établit pas (section 6.5). |
| Avertissement | Signal `AV-…` des sections 9 à 11 (par exemple AV-O-3, réseau d'essai) : il n'est jamais un échec et ne change aucun statut. |
| Borne | Mention, exigée par CT-1 §11.3, des contrôles non exécutés qui limitent le verdict (section 6.6). |
| `periodHash` | SHA-256 des octets « noortrace/manifeste/v0\n » suivis de la forme canonique du manifeste (CT-1 §10.2). Les trois ancres portent sur lui : il engage la racine, les bornes de la période, la continuité avec la période précédente (`prev_period_hash`), le journal et la clé de l'enregistreur, alors qu'horodater la racine seule n'engagerait que la racine (section 16). |
| Autorité d'horodatage | Prestataire qui signe un jeton RFC 3161 (en anglais : TSA). |
| Unité d'horodatage | Le serveur de l'autorité d'horodatage qui signe le jeton (en anglais : TSU). Son certificat est le certificat signataire du jeton (section 9). |
| Unité épinglée | Unité d'horodatage que le fichier d'ancres désigne directement comme autorité : le certificat qu'il donne pour cette autorité est celui de l'unité, et non celui d'une AC au-dessus d'elle. Quand T-7 retient cette autorité (EX-9.13, chemin retenu), le chemin se réduit à ce certificat, dont les dates sont comparées à `genTime`. |
| Jeton | Le jeton d'horodatage RFC 3161 contenu dans `jeton-rfc3161.der`. |
| Attestation en attente | Dans une preuve OpenTimestamps, la promesse d'un calendrier, pas encore reliée à un bloc Bitcoin (R2-F20). |
| Point de contrôle | En-tête Bitcoin (réseau, hauteur, hachage) que le réviseur tient pour authentique ; la chaîne d'en-têtes fournie doit s'y rattacher, et sa preuve de travail est recalculée au-dessus de lui (EX-10.9). |
| Confirmations | Nombre d'en-têtes de la chaîne fournie depuis le bloc attesté, lui compris, jusqu'au dernier : t − h + 1 (EX-10.10). |
| Registre | L'instance dédiée de noorcore qui porte `PeriodRegistry`, `AttestationRegistry` et `RecorderRegistry` (architecture, « Instance dédiée »). |
| Certificat de commit | La proposition signée et au moins un quorum de precommits signés qui ont décidé un bloc du registre, servis par `noor_getCommitCertificate` (`scripts/verify/README.md`). |
| Jeu de validateurs | Identifiants et clés publiques des validateurs du registre ; son hachage est le `valsetHash` des certificats (R3 F14). |
| Quorum | `⌊(N + f) / 2⌋ + 1` signataires distincts parmi N validateurs, avec `f = ⌊(N − 1) / 3⌋` : 3 sur 4 (R3 F15). |
| Dossier CT-1 | Dossier v0 dont les cinq parties réservées sont absentes avec la raison « hors périmètre CT-1 » (vecteurs `spec/vecteurs/ct-1/dossiers`). |
| Entrée à part | Entrée de la ligne de commande qui n'est pas une partie du dossier : en-têtes Bitcoin, pièces, second manifeste (section 4.3). |

## 3. Modèle de confiance

### 3.1 Ce que le vérificateur croit

Le calcul du vérificateur tient pour vrais trois éléments, et rien d'autre
(ce que son résultat signifie suppose en outre ce que dit le paragraphe qui
suit la liste) :

1. **son propre code**, à la version qu'il annonce, avec les schémas de cette
   version. Un réviseur qui ne veut pas croire le binaire le reconstruit et
   compare les octets (section 14), ou relit l'implémentation de référence ;
2. **les primitives cryptographiques** qu'il emploie : SHA-256, Keccak-256,
   Ed25519, ECDSA sur secp256k1, et les algorithmes de signature de
   certificats que la section 9 admet (hypothèses H1 et H2, section 3.5) ;
3. **le fichier d'ancres du réviseur** : les autorités d'horodatage qu'il
   accepte et le statut qu'il leur déclare, le point de contrôle Bitcoin et
   les règles de la chaîne d'en-têtes, l'identifiant de la chaîne du registre,
   les adresses de ses contrats et ses jeux de validateurs avec leurs hauteurs
   de validité, et, s'il les connaît par une autre voie que le registre
   (procès-verbal d'inscription, cérémonie des clés), les clés publiques des
   enregistreurs et leurs clés de chaîne.

Ce que le résultat signifie suppose en outre les hypothèses de 3.5 sur le
monde extérieur : l'autorité d'horodatage (H4), les mineurs (H5), les
validateurs (H6) et le code des contrats (H7). Le vérificateur ne les
contrôle pas. Cette spécification les énonce, et la section 7.8 les
rappelle. Le sens du contrôle 8 suppose aussi que ses règles de calcul,
tirées du code privé de noorcore, sont celles du registre (7.8). Pour le
réviseur, en version 0, croire « son propre code » veut dire croire
l'implémentation de référence, la bibliothèque `ethers` qu'elle importe
(Keccak-256 et signatures secp256k1) et l'environnement Node qui l'exécute,
que cette spécification n'épingle pas (7.8). Un fait externe que l'annexe B
dit non recoupable repose sur la note, R1 à R4, qui le rapporte. La
section 7.8 donne la liste complète de ce qu'un réviseur doit croire.

**EX-3.1** Le vérificateur NE DOIT fonder un statut `reussi` que sur des
calculs faits à partir des entrées de la section 4 et sur les trois éléments
ci-dessus.

**EX-3.2** Le vérificateur NE DOIT PAS lire l'horloge du système pour décider
d'un statut. Toute validité dans le temps se juge à un instant tiré des pièces
(par exemple `genTime` du jeton pour la chaîne de certificats, section 9). Le
verdict est donc le même quel que soit le jour de la vérification, à version
égale du vérificateur et du fichier d'ancres.

**EX-3.3** Le vérificateur NE DOIT ouvrir aucune connexion réseau, ne résoudre
aucun nom et ne consulter aucun magasin de certificats du système
d'exploitation. Les racines de toute validation de certificats sont
construites uniquement depuis le fichier d'ancres. Motif : en Go,
`x509.Certificate.Verify` appelé avec des racines nulles ou issues de
`SystemCertPool` délègue, sous Windows et macOS, au vérificateur de la
plate-forme, qui peut aller chercher des certificats sur le réseau, et lit
`/etc/ssl/certs` sous Linux (R4 F2.02 à F2.06, F2.09 ;
https://pkg.go.dev/crypto/x509). La section 14 dit comment l'absence de
réseau est prouvée.

**EX-3.4** Le vérificateur NE DOIT jamais tirer une ancre du dossier ni d'une
entrée à part. Un certificat embarqué dans le jeton, un jeu de validateurs de
`validateurs.json`, une adresse de contrat de `registre.json` restent
déclaratifs, même quand ils sont identiques à une ancre : leur égalité avec
l'ancre est une vérification, pas une source.

**EX-3.5** Le vérificateur NE DOIT croire aucune affirmation d'un nœud
recopiée dans le dossier : `canonical.matchesCertificate`,
`validatorSetMatchesCertificate`, `quorum`, `validatorSet` et les champs
décodés de la réponse de `noor_getCommitCertificate` sont ignorés ; seules
comptent les lignes brutes signées et les champs d'identité du certificat
(`scripts/verify/README.md` ; R3 F20, F22).

### 3.2 Ce que le vérificateur ne croit pas

Tout ce qui vient du dossier et des entrées à part est déclaratif, sans
exception :

- l'index `dossier.json` : ses SHA-256 n'établissent que la cohérence entre
  l'index et les fichiers, car l'index n'est pas signé ;
- les événements, et en particulier leur `ts`, leurs `effects`, leur
  `delegation` et leur `intent` : ce sont des déclarations de l'enregistreur ;
- `cles.json` : clés publiques, périodes de validité et `source` annoncées ;
- `approbations.json` : jeu d'approbateurs, seuil et `source` annoncés ;
- le jeton, ses certificats embarqués et ses informations de révocation, tant
  que sa chaîne n'est pas rattachée à une autorité du fichier d'ancres ;
- la preuve `.ots` et les en-têtes Bitcoin, tant qu'ils ne sont pas rattachés
  au point de contrôle par O-5 (chaînage des en-têtes, preuve de travail
  recalculée au-dessus du point de contrôle, EX-10.9) ;
- `registre.json`, `certificat-commit.json` et `validateurs.json`, tant que
  les blocs ne sont pas rattachés au jeu de validateurs du fichier d'ancres ;
- les pièces fournies à part et le second manifeste.

Le vérificateur ne consulte pas non plus l'horloge du système (EX-3.2), le
réseau ni les magasins de certificats du système (EX-3.3).

### 3.3 Déclaratif et de confiance, contrôle par contrôle

| Contrôle | Vient du dossier ou d'une entrée à part (déclaratif) | Vient du fichier d'ancres (de confiance) | Établi par le calcul |
|---|---|---|---|
| 1 | `evenement.json`, événements de `voisins.json` et `approbations.json`, pièces | — | Forme et hachage de chaque événement. |
| 2 | `voisins.json` | — | Chaînage par hachages recalculés. |
| 3 | `chemin.json`, `manifeste.json`, `manifeste.sig`, second manifeste | — | Inclusion dans la racine ; `periodHash`. |
| 4 | `jeton-rfc3161.der` et ses certificats | Autorités d'horodatage, politiques admises, statut qualifié déclaré, déclarations de non-révocation ; les intermédiaires et les CRL que le fichier fournit sont vérifiés, non crus, sauf une CRL complète (ni delta ni à `issuingDistributionPoint` critique) qui liste le certificat de l'autorité retenue par T-7. Celle-là est prise sans vérification de signature, parce qu'elle ne peut que retirer la confiance (EX-9.16, section 12.1) | `periodHash` existait au plus tard à l'instant du jeton, selon une autorité du fichier d'ancres. |
| 5 | `preuve.ots`, en-têtes Bitcoin | Réseau, point de contrôle, profondeur minimale (`min_confirmations`) | `periodHash` existait avant la création d'un bloc rattaché au point de contrôle par la chaîne d'en-têtes fournie, preuve de travail recalculée au-dessus du point de contrôle. |
| 6 | `cles.json`, signatures | Clés publiques d'enregistreurs, si le réviseur en fournit (N-3) | La clé nommée a signé ; elle est la clé du fichier d'ancres si celui-ci en donne une sous les mêmes `org_id`, `journal_id` et `key_id` (N-3, EX-12.4). Une clé dont le `key_id` est absent du fichier d'ancres n'est pas comparée, même si le fichier donne d'autres clés pour ce journal (EX-6.14, 7.2). |
| 7 | `approbations.json`, signatures | Aucune ancre d'approbateurs en version 0 | Les adresses nommées ont signé, au seuil déclaré ; pour une demande expirée, aucune signature n'est attachée. |
| 8 | `registre.json`, `certificat-commit.json`, `validateurs.json` | Identifiant de chaîne, adresses des contrats, jeux de validateurs et hauteurs de validité ; clés de chaîne des enregistreurs, si le réviseur en fournit (N-4) | Un quorum du jeu du fichier d'ancres a signé les blocs où les contrats du fichier d'ancres ont émis la clôture et l'ancre de `periodHash` ; l'émetteur de l'ancre est la clé de chaîne du fichier d'ancres si celui-ci en donne une pour la clé du manifeste, sous les mêmes `org_id`, `journal_id` et `key_id` (N-4, EX-12.5). |

**EX-3.6** Le rapport DOIT dire d'où viennent les clés du contrôle 6
(`dossier`, `ancres` ou `registre`, clé par clé quand elles diffèrent) et le
jeu d'approbateurs du contrôle 7 (toujours `dossier` en version 0, qui n'a ni
ancre d'approbateurs ni comparaison avec le registre), et l'énoncé DOIT le
répéter (section 6.5). Une valeur déclarative n'est jamais présentée comme de
confiance.

**EX-3.7** Une différence entre une valeur du dossier et l'ancre
correspondante (clé publique d'enregistreur, adresse de contrat, identifiant
de chaîne, hachage du jeu de validateurs) est un échec de la vérification qui
les compare, et rend le dossier invalide. Pour une clé d'enregistreur,
l'ancre correspondante est celle de même `org_id`, `journal_id` et `key_id`
(EX-12.4). Une non-conformité du fichier
d'ancres lui-même (format, cohérence interne) rend l'entrée inutilisable
(code 2) : le fichier d'ancres n'est pas une pièce du dossier, et son défaut
n'est pas une affirmation sur le dossier.

### 3.4 Adversaires considérés

| Adversaire | Ce qu'on lui suppose | Ce qu'un verdict valide aux huit contrôles réussis l'empêche de faire passer | Ce qu'il peut encore faire |
|---|---|---|---|
| **Opérateur** : le client qui exploite l'agent et l'enregistreur, et qui exporte le dossier | Il lit et réécrit le journal, le dossier et les entrées à part. Selon la classe de garde, c'est-à-dire selon où et comment la clé de l'enregistreur est gardée (CT-2 §11.2), il peut en disposer (classes C et D). Dans les classes A et B, il ne peut pas l'exporter, mais il garde l'usage du signataire que son enregistreur emploie (CT-2 EX-11.4, §11.5). | Sans la clé de l'enregistreur ni l'usage de son signataire : un événement, un voisin, un chemin ou un manifeste modifié (contrôles 1, 2, 3, 6). Avec l'une ou l'autre : seulement une autre version de la période présentée après l'instant du jeton et la création du bloc Bitcoin (4, 5), ou, sous H7 et H6, après l'inscription de sa clôture au registre (8). Avant ces instants, rien ne l'empêche de réécrire et de signer de nouveau toute la période. Dans les deux cas : une signature d'approbateur substituée (7). Pour le contrôle 8, la protection contre une autre version inscrite après la première ne vient pas d'un calcul du vérificateur. Il ne compare pas deux clôtures, ne prouve pas qu'il n'en existe qu'une et ne tire aucune date du registre (7.2, 11.8). Elle vient des conditions d'émission de `PeriodSubmitted` par le contrat : refus d'un doublon et d'une période qui ne suit pas la dernière inscrite du journal, seuil des approbateurs (R3 F36). Elle repose donc sur H7, non vérifiée, et sur H6. Sans H7, une autre version inscrite plus tard passerait le contrôle 8 avec sa propre clôture, dans un bloc plus haut, et seul celui qui connaît la première clôture verrait le conflit. | Fabriquer un journal faux avant la clôture de la période et le faire horodater tel quel ; ne pas journaliser un acte ; choisir les voisins et les pièces qu'il exporte ; ne pas produire un dossier défavorable. |
| **Fournisseur NOORTRACE** : il exploite le registre et publie le vérificateur | Il sert ce qu'il veut par le RPC du registre ; il contrôle les validateurs qu'il opère ; il publie le binaire. | Un reçu, un bloc ou un certificat que le quorum du jeu du fichier d'ancres n'a pas signé (8), tant qu'il contrôle moins d'un quorum ; toute altération des données des contrôles 1 à 7, qu'il ne fournit pas. Exception : la provenance « inscrite au registre » d'une clé vient du contrôle 8 et ne tient contre lui que s'il contrôle moins d'un quorum, sous H7. Pour le code qui exécute les contrôles : un binaire différent du code publié, si le réviseur le reconstruit (section 14, à partir de la phase 2) ; en version 0, une implémentation de référence altérée, si le réviseur relit celle qu'il exécute (3.1, 7.8). | S'il contrôle au moins un quorum des validateurs du jeu, faire passer de faux blocs du registre : le contrôle 8 ne prouve alors rien contre lui. C'est pourquoi aucune date n'est tirée du registre (section 7). Si le réviseur reprend ses adresses de contrats sans les recouper, désigner un contrat qui émet ce qu'il veut (H3, H7 ; section 12.5). En version 0, aucun binaire n'est livré : la parade à un vérificateur altéré est de relire l'implémentation de référence, qu'il publie aussi, en croyant l'environnement Node et la bibliothèque `ethers` (3.1, 7.8). Les règles de calcul du contrôle 8 viennent du code privé de noorcore et d'expériences sur le réseau de développement : un réviseur sans accès à ce code les tient du fournisseur NOORTRACE (7.8). Les adresses de contrats, l'identifiant de chaîne et les jeux de validateurs qu'il publie (EX-13.11) reposent sur lui s'ils ne sont pas recoupés (12.5). Sans relecture ni recoupement, la confiance du réviseur repose sur lui par ces voies. |
| **Enregistreur compromis** : un attaquant détient sa clé Ed25519, sa clé de chaîne, ou les deux | Il signe ce qu'il veut sous ces clés. | La réécriture d'une période déjà horodatée (4, 5) ; celle d'une période déjà inscrite au registre, sous H7 et H6 seulement (le contrat refuse une seconde clôture, R3 F36 ; voir la ligne « Opérateur »). | Signer de faux événements dans la période en cours, avant son horodatage : la fenêtre est la période, une heure, plus le délai d'obtention du jeton (CT-2 EX-11.17). |
| **Autorité d'horodatage** malhonnête ou compromise | Elle signe n'importe quel `genTime`. | Un jeton sur une autre donnée que `periodHash` (4) ; un jeton d'une autorité que le réviseur n'a pas choisie (4). | Antidater ou postdater un jeton. Seul le contrôle 5 donne une borne de temps indépendante d'elle. |
| **Validateurs minoritaires** : au plus f = ⌊(N − 1)/3⌋ validateurs du jeu du fichier d'ancres | Ils signent n'importe quoi. | Un certificat de commit sans le quorum (8). | Rien de plus, sous l'hypothèse H6 (section 3.5). |
| **Fournisseur d'en-têtes Bitcoin** : l'exportateur, ou un mineur | Il fournit les en-têtes qu'il veut. | Un en-tête sans la preuve de travail exigée, ou non rattaché au point de contrôle (5). | Miner lui-même, au-dessus du point de contrôle, autant de blocs que la chaîne fournie en contient, s'il en a la puissance ; sur un réseau d'essai, c'est immédiat (hypothèse H5). |

### 3.5 Hypothèses

Les phrases de la section 7 sont vraies sous ces hypothèses ; si l'une tombe,
ce qui en dépend tombe avec elle.

| H | Hypothèse | Contrôles qui en dépendent | Source ou état |
|---|---|---|---|
| H1 | SHA-256 et Keccak-256 résistent aux collisions et aux secondes préimages. | tous | — |
| H2 | Ed25519, ECDSA sur secp256k1 et les signatures de certificats admises ne se forgent pas sans la clé privée. | 3, 4, 6, 7, 8 | — |
| H3 | Le fichier d'ancres dit vrai : chaque autorité, point de contrôle, adresse, jeu de validateurs et clé qu'il contient est bien celui que le réviseur croit ; chaque autorité d'horodatage était digne de confiance à l'instant `genTime` des jetons qu'on lui rattache (certificat dans ses dates, non révoqué, statut déclaré exact), ce que le vérificateur ne contrôle pas, sauf la révocation de son certificat quand une CRL du fichier d'ancres la porte (EX-9.16), et ses dates quand l'autorité est l'unité épinglée elle-même, dont les dates sont contrôlées comme celles du certificat signataire (EX-9.13). | 4, 5, 6, 8 | section 12 |
| H4 | L'autorité d'horodatage n'a pas signé un `genTime` faux, et sa clé n'était pas compromise à `genTime`. | 4 | RFC 3161 §4 (R1 F1.21), https://www.rfc-editor.org/rfc/rfc3161.txt |
| H5 | Aucun adversaire n'a pu miner, au-dessus du point de contrôle, autant de blocs que la chaîne fournie en contient. Sur un réseau d'essai, cette hypothèse ne tient pas. | 5 | livre blanc Bitcoin §11 (R2-F57), https://bitcoin.org/bitcoin.pdf |
| H6 | Au plus f validateurs du jeu du fichier d'ancres sont fautifs, avec N ≥ 3f + 1. | 8 | Énoncée par le commentaire de `core/consensus/quorum.go:3-12` de noorcore (R3 NV2 ; formule du quorum, R3 F15) ; la propriété de sûreté n'a pas été relue dans une source primaire du protocole : non vérifié (R3 NV2). Les règles de calcul du contrôle 8 (énumérées en 7.8) sont tirées du code de noorcore et d'expériences sur le réseau de développement (annexe B.3). |
| H7 | Le code déployé aux adresses de contrats du fichier d'ancres est celui de `contracts/` (`PeriodRegistry`, `AttestationRegistry`, `RecorderRegistry`). | 8, pour le sens que l'énoncé donne aux journaux émis par les contrats, y compris la provenance « inscrite au registre » (F2) et la mention « clé de chaîne inscrite au bloc … » (R-10) | Non vérifié (R3 NV7). |

## 4. Entrées

### 4.1 Vue d'ensemble

| Entrée | Option (section 8.2) | Fournie par | Nature | Sans elle |
|---|---|---|---|---|
| Dossier v0, un répertoire | argument | exportateur | déclarative | rien n'est vérifié (code 2) |
| En-têtes Bitcoin | `--entetes-bitcoin` | exportateur (CT-5) ou réviseur | déclarative | contrôle 5 non exécuté, raison `partie_absente`, si `preuve.ots` porte une attestation Bitcoin |
| Pièces fournies à part | `--pieces` | client | déclaratives | E-6 ne vérifie que les valeurs en ligne |
| Second manifeste | `--second-manifeste` | exportateur | déclaratif | P-5 sans la continuité de CT-1 §10.3 |
| Fichier d'ancres | `--ancres` | réviseur | de confiance | vérifications qui exigent une ancre non exécutées, raison `ancre_absente` |

### 4.2 Le dossier v0

Le dossier est celui de CT-1 §11 : un répertoire, son index `dossier.json`,
douze parties toujours déclarées dans l'ordre de CT-1 §11.1, chacune présente
avec son SHA-256 ou absente avec une raison. CT-6 ne change ni la version
(`0`), ni les noms, ni l'ordre des parties ; il fixe le contenu des cinq
parties réservées :

| Partie | Fichier | Contenu | Contrôle | Format |
|---|---|---|---|---|
| `jeton_rfc3161` | `jeton-rfc3161.der` | jeton RFC 3161 dont l'empreinte horodatée est `periodHash` | 4 | section 9 |
| `preuve_ots` | `preuve.ots` | preuve OpenTimestamps au format officiel, dont l'empreinte de fichier est `periodHash` | 5 | section 10 |
| `registre` | `registre.json` | en-têtes de blocs, reçus, index et journaux des transactions du registre | 8 | section 11 |
| `certificat_commit` | `certificat-commit.json` | un certificat de commit par bloc que cite `registre.json` | 8 | section 11 |
| `validateurs` | `validateurs.json` | jeu de validateurs déclaré par l'exportateur ; facultative, elle ne sert qu'au contrôle de cohérence R-3 | 8 | section 11 |

**EX-4.1** Le vérificateur lit un seul dossier par exécution. Il ignore les
fichiers du répertoire que `dossier.json` ne déclare pas (CT-1 §11.1) et n'en
tire rien, pas même une ancre.

**EX-4.2** Une partie réservée présente DOIT être vérifiée : D-2 contrôle son
SHA-256, et les vérifications de son contrôle s'exécutent (sections 9 à 11).
Un vérificateur conforme à CT-6 NE DOIT PAS ignorer une partie présente.

**EX-4.3** Une partie réservée absente rend son contrôle `non_execute`, avec
la raison `hors_perimetre_version` si la raison déclarée dans l'index est exactement
« hors périmètre CT-1 », et `partie_absente` sinon (`hors_perimetre_version`
est la valeur de la section 6.2). Les parties requises de chaque contrôle
sont les parties du dossier que nomme la table 5.1 : si l'une manque, le
contrôle n'est pas exécuté. Une entrée à part n'est jamais une partie
requise : sans fichier d'en-têtes, seules O-4 à O-6 ne s'exécutent pas
(EX-4.5). `validateurs.json` n'est pas requise : son absence ne laisse non exécutée que
R-3, sans effet sur le contrôle 8 (section 11).

**EX-4.4** Le rapport donne le SHA-256 des octets de `dossier.json`
(`inputs.dossier.index_sha256`), qui désigne sans ambiguïté le dossier
vérifié : quand D-2 réussit, l'index porte le SHA-256 de chaque partie
présente, et fixe donc tout le dossier.

### 4.3 Les entrées à part

CT-1 §11.1 range les pièces fournies à part et le second manifeste parmi les
entrées de la ligne de commande, pas parmi les parties du dossier. CT-6 y
ajoute la chaîne d'en-têtes Bitcoin, pour la même raison : les douze parties
du dossier v0 sont fixées.

**EX-4.5** En-têtes Bitcoin. La chaîne d'en-têtes qui relie le bloc attesté
par `preuve.ots` au point de contrôle du réviseur est lue dans le fichier que
désigne `--entetes-bitcoin`, au format de la section 10. Elle est
déclarative : le contrôle 5 recalcule sa preuve de travail et son rattachement
au point de contrôle du fichier d'ancres. Sans ce fichier, O-5 est
`non_execute`, raison `partie_absente`, et O-4 et O-6 avec elle (EX-5.5) ;
O-1, O-2, O-3 et O-7 s'exécutent (EX-5.3). Si aucune n'échoue, le contrôle 5
est `non_execute`, raison `partie_absente`.

**EX-4.6** Pièces fournies à part. `--pieces` désigne un répertoire où chaque
pièce est nommée par son `sha256` en hexadécimal minuscule, sans `0x` (CT-2
EX-8.9). Le vérificateur ne lit que les fichiers dont le nom est le `sha256`
d'une référence d'un événement du dossier, et vérifie leur `sha256` et leur
`length` (E-6). Une pièce référencée mais non fournie n'est pas une erreur :
la référence reste une empreinte, et l'énoncé ne dit rien de son contenu.

**EX-4.7** Second manifeste. `--second-manifeste` désigne un manifeste v0 du
même journal, qui précède ou suit celui du dossier. Le vérificateur le place
d'après `period_start` et contrôle la continuité de CT-1 §10.3 dans P-5. Un
manifeste d'un autre journal, ou ni précédent ni suivant, met P-5 en échec.
La continuité prouve que les deux manifestes se chaînent. Avec le manifeste
précédent, elle l'authentifie par `prev_period_hash`, que la signature du
manifeste prouvé couvre ; avec le manifeste suivant, elle ne prouve rien sur
lui, dont la signature n'est pas vérifiée.

### 4.4 Le fichier d'ancres

**EX-4.8** Le fichier d'ancres est désigné par `--ancres`. Il est écrit et
contrôlé par le réviseur, au schéma
`spec/schemas/ancres-confiance-v0.schema.json` (section 12). Le vérificateur
ne le cherche nulle part ailleurs : ni dans le dossier, ni dans un répertoire
par défaut, ni dans une variable d'environnement, ni sur le réseau.

**EX-4.9** Sans fichier d'ancres, le vérificateur exécute toutes les
vérifications qui n'en ont pas besoin (EX-5.3) et rend les autres
`non_execute`, raison `ancre_absente`. Un fichier d'ancres qui ne contient pas
l'ancre dont une vérification a besoin (aucune autorité d'horodatage, ou un
certificat signataire qui n'est ni dans le jeton ni dans le fichier, T-4 ;
aucune ancre `bitcoin`, c'est-à-dire `bitcoin` nul ; aucun jeu de validateurs
valable à la hauteur du bloc) produit le même résultat pour cette
vérification. Un fichier qui contient des autorités dont aucune ne termine un
chemin depuis le certificat signataire fait échouer T-7 (EX-9.13). Une ancre
`bitcoin` d'un autre réseau que le fichier d'en-têtes fait échouer O-5
(EX-10.9, règle 1). Un point de contrôle hors des en-têtes fournis laisse O-5
`non_execute` (`ancre_absente`, EX-10.9, règle 3).

**EX-4.10** Un fichier d'ancres illisible, qui n'est pas du JSON, qui ne suit
pas son schéma, ou qui échoue aux vérifications N- de conformité de la
section 12 rend l'entrée inutilisable : code 2, type d'erreur
`ancres_inutilisables`, aucune vérification du dossier n'est rapportée. Le
vérificateur n'emploie jamais une partie d'un fichier d'ancres défectueux.

### 4.5 Lecture et limites

**EX-4.11** Une partie du dossier qui se lit mais qui est mal formée, ou qui
dépasse sa limite de taille, est inexploitable : elle met en échec la
vérification qui la porte (CT-1 §11.4 pour les parties de CT-1 ; T-1, O-1,
R-1 et R-3 pour les parties réservées), les vérifications qui en dépendent sont
`non_execute`, raison `prerequis_en_echec`, et le dossier est invalide. Une
partie déclarée présente mais absente du répertoire est un échec de D-2
(CT-1).

**EX-4.12** Une entrée désignée par une option (fichier d'ancres, en-têtes
Bitcoin, second manifeste, répertoire de pièces) que le système de fichiers
refuse (chemin inexistant, droits, pas un fichier), qui n'est pas du JSON,
qui ne suit pas son schéma ou qui dépasse sa limite de taille rend l'entrée
inutilisable : code 2 ; type `ancres_inutilisables` pour le fichier d'ancres,
quel que soit le défaut (EX-4.10), sinon `taille_depassee` pour une limite et
`entree_illisible` pour tout autre défaut ; `error.check` vaut `N-1` pour le
fichier d'ancres, `N-2` pour le fichier d'en-têtes et `null` pour les autres
entrées (section 12).
Un fichier d'en-têtes conforme dont le chaînage, la preuve de travail ou
l'en-tête au point de contrôle sont faux fait échouer O-5 ; un fichier
d'en-têtes qui ne contient pas la hauteur du point de contrôle laisse O-5 non
exécutée (`ancre_absente`, EX-10.9) ; un second manifeste conforme qui ne se chaîne pas fait
échouer P-5 ; une pièce dont les octets ne correspondent pas à sa référence
fait échouer E-6. `dossier.json` absent, ou qui n'est pas du JSON, reste le
code 2 de CT-1 (`dossier_illisible`).

**EX-4.13** Le vérificateur lit chaque entrée avec une borne et s'arrête à
la limite de la table ci-dessous sans lire au-delà. Ces limites sont des
choix de cette spécification : elles dépassent largement les tailles
observées, qu'un dossier conforme n'approche pas. La section 15 (sûreté du
vérificateur) emploie les mêmes valeurs et y ajoute les bornes des
analyseurs.

| Entrée | Limite | Taille observée |
|---|---|---|
| `dossier.json` | 1 Mio | 2 698 octets (`valide-seq-7`) |
| chacune des six autres parties JSON de CT-1 | 16 Mio | 4 718 octets au plus (`voisins.json` de `valide-seq-7`) |
| `jeton-rfc3161.der` | 64 Kio (EX-9.3) | 4 521 octets (jeton qualifié réel, extrait d'une réponse de 4 530 octets, R1 F7.03) |
| `preuve.ots` | 256 Kio (EX-10.2) | 688 octets (`hello-world.txt.ots`, R2-F25) |
| `registre.json` | 64 Mio | non mesurée |
| `certificat-commit.json` | 64 Mio | 7 075 à 7 782 octets par certificat (R3 F47) |
| `validateurs.json` | 1 Mio | non mesurée |
| fichier d'en-têtes Bitcoin | 200 000 en-têtes (EX-10.3), 64 Mio | 80 octets par en-tête (R2-F43) |
| second manifeste | 1 Mio | 629 octets (`manifeste.json` de `valide-seq-7`) |
| fichier d'ancres | 16 Mio | non mesurée |
| une pièce fournie à part | 1 Gio | non mesurée |
| profondeur d'imbrication JSON | 128 niveaux | — |
| profondeur d'imbrication DER | 32 niveaux (EX-9.4) | — |
| chemin d'une preuve `.ots`, de la racine à une attestation | 255 opérations (EX-10.2) | 256 refusées par la bibliothèque officielle (R2-F18) |

## 5. Les huit contrôles

### 5.1 Table des contrôles

| N° | Contrôle de l'architecture | Vérifications | Parties et entrées requises | Ancres | Ce qu'il établit quand il réussit |
|---|---|---|---|---|---|
| 1 | Hachage canonique de l'événement et égalité avec `hash` | E-1, E-2, E-3, E-4, E-6, E-7 | `evenement.json` ; pièces si fournies | — | Chaque événement du dossier a la forme de CT-1 et le hachage qu'il annonce. |
| 2 | Continuité de la chaîne avec les voisins fournis | C-1, C-2, P-3 | `voisins.json` | — | L'événement est relié à ses voisins par leurs hachages recalculés ; un voisin de la même période porte un `ts` déclaré dans ses bornes, et un voisin de la période adjacente (l'événement étant le premier ou le dernier de la sienne) un `ts` déclaré hors d'elle (P-3). |
| 3 | Chemin de Merkle jusqu'à la racine | M-1, M-2, M-3, P-1, P-2, P-3, P-4, P-5 | `chemin.json`, `manifeste.json`, `manifeste.sig` ; second manifeste si fourni | — | L'événement est la feuille d'indice `seq − first_seq` de l'arbre dont la racine est dans le manifeste ; `periodHash` est recalculé et signé par la clé déclarée. |
| 4 | Jeton RFC 3161 sur `periodHash` | T-1 à T-11 (section 9 ; T-11 sans effet sur le statut) | `jeton-rfc3161.der` | autorités d'horodatage, politiques admises, révocation, statut qualifié déclaré | `periodHash` existait au plus tard à `genTime` augmenté de la précision du jeton, selon une autorité du fichier d'ancres. Chaque certificat du chemin qui mène à cette autorité, le sien excepté, était valide à `genTime` (T-7) et, à cet instant, non révoqué selon une CRL à signature vérifiée (du fichier d'ancres ou du jeton) ou selon une déclaration du fichier d'ancres, de date postérieure ou égale à `genTime` (T-10 ; portée de cette preuve en 7.2). Les dates du certificat de l'autorité ne sont pas contrôlées (sauf unité épinglée, dont les dates sont contrôlées comme celles du certificat signataire), et sa révocation ne l'est que si une CRL du fichier d'ancres la porte (EX-9.13, EX-9.16, H3). |
| 5 | Preuve OpenTimestamps contre les en-têtes Bitcoin | O-1 à O-7 (section 10) | `preuve.ots` ; en-têtes Bitcoin pour O-4 à O-6 (EX-4.5) | réseau, point de contrôle, profondeur minimale | `periodHash` existait avant la création d'un bloc Bitcoin relié au point de contrôle par la chaîne d'en-têtes fournie, preuve de travail recalculée au-dessus du point de contrôle, sous k confirmations. |
| 6 | Signature Ed25519 de l'enregistreur | E-8, E-10, E-11, C-3, P-5 ; N-3 (section 12) si le fichier d'ancres donne des clés | `cles.json`, `evenement.json`, `voisins.json`, `manifeste.sig` | clés d'enregistreurs, facultatives | La clé nommée a signé l'événement, ses voisins et le manifeste. Le `ts` de chaque événement et le `generated_at` du manifeste, tels que déclarés, tombent dans la période de validité que `cles.json` annonce pour la clé qui les signe (E-11, P-5), ce qui ne date pas la signature ; la clé nommée est celle du fichier d'ancres si celui-ci en donne une sous les mêmes `org_id`, `journal_id` et `key_id` (N-3, EX-12.4). Une clé dont le `key_id` est absent du fichier d'ancres n'est pas comparée, même si le fichier donne d'autres clés pour ce journal (EX-6.14, 7.2). |
| 7 | Signatures des approbateurs et respect du seuil | E-5, E-9, A-1, A-2, A-3, A-4 | `approbations.json` quand `approval` n'est pas nul | — | Les adresses nommées ont signé la décision liée à l'événement, en nombre au moins égal au seuil du jeu déclaré. Pour une demande expirée (`decision` = `expire`), la décision liée à l'événement ne porte aucune signature (A-3) : aucun nombre de signatures n'est comparé au seuil, que l'énoncé rappelle. |
| 8 | Inclusion de la transaction du registre dans un bloc certifié par un quorum | R-1 à R-10 (section 11 ; R-3 et R-10 sans effet sur le statut) ; N-4 (section 12) si le fichier d'ancres donne la clé de chaîne de la clé du manifeste | `registre.json`, `certificat-commit.json` ; `validateurs.json` facultative | identifiant de chaîne, adresses des contrats, jeux de validateurs et leurs hauteurs ; clé de chaîne d'enregistreur, facultative | Un quorum du jeu du fichier d'ancres a signé les blocs où les contrats du fichier d'ancres ont émis `PeriodSubmitted` avec ce `periodHash` et `Anchored` avec son `anchorFingerprint`. |

Dans la colonne « Parties et entrées requises », les entrées à part ne sont
pas des parties requises (EX-4.3). Sans fichier d'en-têtes, seules O-4 à O-6
ne s'exécutent pas, avec la raison `partie_absente` (EX-4.5). Sans pièces ni
second manifeste, E-6 et P-5 s'exécutent sur ce que le dossier contient
(4.1).

D-1 et D-2 ne servent aucun contrôle de l'architecture (CT-1 §11.4) : elles
portent sur l'index ; leur échec rend le dossier invalide sans mettre en échec
l'un des huit contrôles. P-3 sert les contrôles 2 et 3, P-5 les contrôles 3
et 6, comme dans la colonne « Contrôle de l'architecture » de CT-1 §11.4.

**EX-5.1** Le vérificateur exécute les vérifications de cette table, et
seulement elles ; aucune autre règle n'entre dans le verdict. Une vérification
qui sert deux contrôles compte pour les deux.

### 5.2 Ordre d'exécution

**EX-5.2** Le vérificateur procède dans cet ordre :

1. analyse des options, lecture du fichier d'ancres et du fichier
   d'en-têtes, vérifications N-1 et N-2 de leur conformité (code 2 en cas
   d'échec, EX-4.10 et EX-4.12) ;
2. lecture de `dossier.json` (code 2 s'il est absent ou n'est pas du JSON),
   puis D-1 et D-2 ;
3. vérifications de CT-1 dans l'ordre de CT-1 §11.4 (E-, C-, M-, P-, A-),
   E-6 avec les pièces fournies à part et P-5 avec le second manifeste ;
4. vérifications T- (contrôle 4), O- (contrôle 5), R- (contrôle 8), chaque
   famille dans l'ordre de ses numéros ;
5. vérifications N-3, qui compare les clés de `cles.json` à celles du
   fichier d'ancres (contrôle 6), puis N-4, qui compare l'émetteur de l'ancre
   du registre à la clé de chaîne du fichier d'ancres (contrôle 8) ;
6. statuts des contrôles, verdict, énoncé, borne (section 6).

Le rapport suit cet ordre : D, E, C, M, P, A (CT-1 §11.4), puis T, O, R, N,
qui est aussi celui des listes de l'`attendu.json` des vecteurs (EX-A.3).
L'ordre ne change aucun statut : chaque vérification ne dépend que de ses
entrées et de ses prérequis (section 5.3).

### 5.3 Dépendances

| Contrôle | Pour s'exécuter, il lui faut | Pour entrer dans l'énoncé, il faut aussi |
|---|---|---|
| 1 | `evenement.json` exploitable | — |
| 2 | les hachages recalculés du contrôle 1 | 1 réussi |
| 3 | les hachages recalculés du contrôle 1 ; `manifeste.json` exploitable | 1 réussi |
| 4 | `jeton-rfc3161.der` ; pour T-2, `periodHash` recalculé (P-1 : `manifeste.json` conforme et de forme canonique calculable, EX-5.4) | 1 et 3 réussis |
| 5 | `preuve.ots` ; pour O-2, `periodHash` recalculé (EX-5.4) | 1 et 3 réussis |
| 6 | `cles.json` exploitable (E-8) | 1 réussi |
| 7 | `approbations.json` quand `approval` n'est pas nul | 1 réussi |
| 8 | `registre.json`, `certificat-commit.json` ; pour R-9 et R-10, `periodHash` recalculé et le manifeste (`org_id` et `journal_id` pour `anchorFingerprint`, EX-5.4) | 1 et 3 réussis |

En version 0, la colonne « Pour entrer dans l'énoncé » ne retire jamais
rien. Pour un verdict valide ou incomplet, les contrôles 1, 2, 3 et 6 sont
toujours réussis (6.4). Un verdict invalide a l'énoncé de EX-6.9, sans
fragments F. La colonne dit de quels contrôles dépend le sens d'une
proposition. Celles des contrôles 4, 5 et 8 portent sur le manifeste. Elles
ne disent quelque chose de l'événement que parce que les contrôles 1 et 3
l'y incluent (F1).

**EX-5.3** Une vérification qui n'a pas besoin d'ancre s'exécute même sans
fichier d'ancres : par exemple, l'empreinte du jeton égale à `periodHash`,
l'empreinte de `preuve.ots` égale à `periodHash`, le `BFTBlockHash` recalculé
égal au `blockHash` du certificat. Son échec rend le dossier invalide : une
pièce qui contredit le dossier le contredit quelles que soient les ancres.

**EX-5.4** Les vérifications T-, O- et R- emploient le `periodHash` recalculé
depuis `manifeste.json` (CT-1 §10.2), jamais `manifeste.sig.period_hash` ni
une valeur lue dans la partie qu'elles vérifient. Exigent `periodHash`, ou le
manifeste exploitable, et seulement elles : T-2, O-2, R-9 et R-10 ; N-4, qui
nomme la clé du manifeste, ne figure au rapport que si P-1 a réussi
(EX-12.5). Quand P-1 n'a pas réussi, ces quatre vérifications sont
`non_execute`, raison `prerequis_en_echec` ; toutes les autres vérifications
T-, O- et R- s'exécutent comme leurs tables le disent (9.5, 10.4, 11.4).

**EX-5.5** Une vérification dont un prérequis a échoué, ou n'a pas été
exécuté avec la raison `prerequis_en_echec`, est `non_execute`, raison
`prerequis_en_echec`. Une vérification dont un prérequis n'a pas été exécuté
pour une raison admise est `non_execute` avec cette raison, comme A-2 à A-4
quand `approbations.json` est absent (CT-1 §11.4) : sans fichier d'ancres,
T-10 et T-11 suivent T-7, et R-5 suit R-2, avec la raison `ancre_absente`.
Quand plusieurs raisons admises s'appliquent à une vérification, elle porte la
première dans l'ordre de EX-6.5. Elle n'est jamais `reussi`.

**EX-5.6** Les vérifications T-, O- ou R- d'un contrôle dont une partie
requise est absente (EX-4.3) ne s'exécutent pas et ne figurent pas dans le
rapport : le contrôle porte la raison. De même, N-3, qui compare les clés de
`cles.json` à celles du fichier d'ancres, ne s'exécute et ne figure que si le
fichier d'ancres donne des clés pour l'organisation et le journal du dossier ;
sinon le contrôle 6 repose sur les seules vérifications de CT-1, et la
provenance de chaque clé est `registre` ou `dossier` selon la table des
provenances de EX-6.8. N-4 ne s'exécute et ne figure que si le fichier
d'ancres donne une clé de chaîne pour la clé du manifeste et que les parties
du contrôle 8 sont présentes (EX-12.5). Les vingt-huit vérifications de CT-1
figurent toujours toutes, comme dans CT-1.

## 6. Verdicts

### 6.1 Statut d'une vérification

**EX-6.1** Chaque vérification a l'un de trois statuts : `reussi` (exécutée,
la règle tient), `echoue` (exécutée, la règle ne tient pas), `non_execute`
(pas exécutée, avec une raison de la section 6.2). Une vérification
`non_execute` n'est jamais comptée comme réussie. `reussi` dit que la règle
tient sur les entrées ; ce que cela prouve dépend des hypothèses de 3.5. Sur
un réseau d'essai, H5 ne tient pas, et un contrôle 5 réussi ne prouve rien
(AV-O-3).

### 6.2 Raisons de non-exécution : liste fermée

| Raison | Sens | S'applique à | Admise |
|---|---|---|---|
| `partie_absente` | La partie du dossier ou l'entrée à part qu'il faut est déclarée absente dans l'index, avec une raison, ou n'a pas été fournie ; ou bien la partie est présente mais ne porte pas encore ce qui la rend vérifiable (preuve OpenTimestamps sans attestation Bitcoin, O-7) ; ou bien un élément attendu manque dans une partie présente (`registre.json` sans entrée `inscription`, R-10). Le nom reprend la « partie absente » de CT-1 §11.4. Pour une entrée à part, il veut dire « entrée non fournie », sans faire de cette entrée une partie requise (EX-4.3). | vérifications, contrôles | oui |
| `ancre_absente` | Aucun fichier d'ancres, ou le fichier ne contient pas l'ancre exigée (y compris un certificat signataire qui n'est ni dans le jeton ni dans le fichier d'ancres, section 9, et une chaîne d'en-têtes qui ne couvre pas les hauteurs nécessaires ou n'atteint pas la profondeur `min_confirmations`, section 10). | vérifications, contrôles | oui |
| `hors_perimetre_version` | La partie est absente avec la raison exacte « hors périmètre CT-1 » (dossier produit pour la seule CT-1), ou la pièce emploie une construction que la version 0 du vérificateur ne vérifie pas (par exemple une opération OpenTimestamps hors du profil de la section 10). | vérifications, contrôles | oui |
| `piece_hors_dossier` | L'objet de la vérification n'est pas dans le dossier : l'événement de demande, pour A-4 (CT-1 §11.4). | vérifications seulement | oui |
| `prerequis_en_echec` | Une vérification dont elle dépend a échoué ou n'a pas été exécutée pour cette même raison (EX-5.5), ou une pièce dont elle dépend est inexploitable. | vérifications, contrôles | non |

Un contrôle non exécuté pour une raison admise l'est pour l'une des trois
raisons du modèle de verdict : partie absente, ancre absente, hors périmètre
de la version. Une preuve OpenTimestamps qui ne porte que des attestations en
attente est une partie absente au sens de cette table : l'attestation Bitcoin
manque (section 10). Les deux autres valeurs ne servent qu'aux
vérifications : `piece_hors_dossier` reprend le seul cas admis de CT-1 en
dehors des parties absentes (A-4) ; `prerequis_en_echec` nomme le « non
exécuté sans raison admise » de CT-1 §11.4 et apparaît aussi au niveau d'un
contrôle, mais seulement dans un dossier déjà invalide.

**EX-6.2** Une vérification ou un contrôle `non_execute` DOIT porter
exactement une raison de cette table ; aucune autre valeur n'est admise. Le
texte libre (`detail`) peut préciser la raison, jamais la remplacer.

**EX-6.3** Correspondance avec CT-1 : A-2, A-3 et A-4 non exécutées parce que
`approbations.json` est absent avec la raison « aucune approbation liée » →
`partie_absente` ; A-4 non exécutée parce que l'événement de demande n'est pas
dans le dossier → `piece_hors_dossier` ; toute autre non-exécution d'une
vérification de CT-1 (index, événement, voisins, chemin, manifeste, signature
de manifeste ou `cles.json` inexploitables, clé absente, validité non
annoncée) → `prerequis_en_echec`. Cette correspondance reproduit exactement la
distinction de CT-1 §11.4 entre raisons admises et non admises.

### 6.3 Statut d'un contrôle

**EX-6.4** Sauf règle propre de sa section (EX-9.18 pour le contrôle 4,
EX-10.12 pour le contrôle 5, EX-11.20 pour le contrôle 8, qui prévalent), le
statut d'un contrôle se déduit de ses vérifications (table 5.1) :

1. `echoue` si au moins une de ses vérifications est `echoue` ;
2. sinon `non_execute` si une partie requise du contrôle est absente
   (EX-4.3), ou si au moins une de ses vérifications est `non_execute` pour
   une autre raison que `piece_hors_dossier`, sauf les vérifications déclarées
   sans effet sur le statut quand elles ne sont pas exécutées (en version 0 :
   T-11, EX-9.17 ; R-3 et R-10, EX-11.20 ; N-3, EX-12.4 ; N-4, EX-12.5) ;
3. sinon `reussi`.

**EX-6.5** Sauf règle propre de sa section, la raison d'un contrôle
`non_execute` est la première de cette liste qui s'applique à l'une de ses
parties requises ou de ses vérifications : `prerequis_en_echec`,
`hors_perimetre_version`, `partie_absente`, `ancre_absente`. Cet ordre fait
passer ce qui invalide avant ce qui borne, et ce qui tient au dossier avant
ce qui tient aux ancres.

**EX-6.6** Un contrôle n'est jamais `reussi` quand une ancre qu'il exige
manque, quand une de ses parties requises est absente, ou quand sa preuve
OpenTimestamps n'a que des attestations en attente. Aucune implémentation ne
traite une ancre absente comme un succès.

### 6.4 Verdict global

**EX-6.7** Le verdict est :

1. `invalide` si au moins une vérification, de n'importe quelle famille (D-
   comprise), est `echoue`, ou `non_execute` avec la raison
   `prerequis_en_echec` ;
2. sinon `incomplet` si l'option `--exiger` (section 8.2) nomme un contrôle
   dont le statut n'est pas `reussi` ;
3. sinon `valide`.

Le rapport liste dans `failed_checks` les vérifications en échec et dans
`blocking_unexecuted` celles qui sont non exécutées sans raison admise, dans
l'ordre du rapport.

`valide` ne veut pas dire « huit contrôles réussis ». Il veut dire : rien n'a
échoué, et ce qui n'a pas été exécuté l'a été pour une raison admise.
L'énoncé dit ce qui a été prouvé (section 6.5) ; la section 7 dit ce que cela
vaut. Pour un verdict `valide` ou `incomplet`, les contrôles 1, 2, 3 et 6 sont
toujours réussis : leurs parties sont obligatoires (CT-1 §11.1), donc ils ne
peuvent être non exécutés que pour `prerequis_en_echec`, qui invalide. Seuls
les contrôles 4, 5, 7 et 8 peuvent être non exécutés pour une raison admise.

### 6.5 Énoncé : construction exacte

**EX-6.8** Pour un verdict `valide` ou `incomplet`, l'énoncé est une phrase
assemblée à partir des fragments ci-dessous, dans l'ordre F0 à F8, sans
aucun autre caractère ; `␣` y note une espace (U+0020). Un fragment
conditionnel n'apparaît que si sa condition est vraie. Le vérificateur produit l'énoncé en français et en anglais. F0 à F3
portent sur l'événement. F4, F5 et F6 sont les propositions que les
sections 9, 10 et 11 fournissent sur le manifeste ; F1 les relie à
l'événement, puisqu'il le dit inclus dans ce manifeste. F7 dit ce qui n'est
pas prouvé. Les accolades désignent des valeurs (EX-6.11).

| Fragment | Condition | Français | Anglais |
|---|---|---|---|
| F0 | toujours | `L'événement seq {seq} (hachage {hash}) du journal {journal_id} de l'organisation {org_id}` | `Event seq {seq} (hash {hash}) of journal {journal_id} of organisation {org_id}` |
| F1 | toujours | `␣est bien formé, {voisinage} et inclus dans la période du {period_start} au {period_end} close par le manifeste {period_hash}` | `␣is well-formed, {neighbours} and included in the period from {period_start} to {period_end} closed by manifest {period_hash}` |
| F2 | toujours, deux clés | `␣; l'événement est signé par la clé d'enregistreur {cle_evenement} et le manifeste par la clé {cle_manifeste}, {provenance}` | `; the event is signed by recorder key {cle_evenement} and the manifest by key {cle_manifeste}, {provenance}` |
| F2 | toujours, une clé | `␣; l'événement est signé, comme le manifeste, par la clé d'enregistreur {cle_evenement}, {provenance}` | `; the event is signed, like the manifest, by recorder key {cle_evenement}, {provenance}` |
| F3 | contrôle 7 réussi, `{decision}` = `approuve` | `␣; l'événement a été approuvé par {approbateurs} ({nb} signatures, seuil de {required} sur {size} du jeu déclaré par le dossier)` | `; the event was approved by {approbateurs} ({nb} signatures, threshold {required} of {size} of the set declared by the dossier)` |
| F3 | contrôle 7 réussi, `{decision}` = `refuse` | `␣; l'événement porte un refus signé par {approbateurs} ({nb} signatures, seuil de {required} sur {size} du jeu déclaré par le dossier)` | `; the event carries a refusal signed by {approbateurs} ({nb} signatures, threshold {required} of {size} of the set declared by the dossier)` |
| F3 | contrôle 7 réussi, `{decision}` = `expire` | `␣; l'événement porte une demande d'approbation expirée sans signature (seuil de {required} sur {size} du jeu déclaré par le dossier)` | `; the event carries an approval request that expired without signature (threshold {required} of {size} of the set declared by the dossier)` |
| F4 | contrôle 4 réussi | `␣;␣` suivi de la proposition française de EX-9.20 | `;␣` suivi de la proposition anglaise de EX-9.20 |
| F5 | contrôle 5 réussi | `␣;␣` suivi de la proposition française de EX-10.15 | `;␣` suivi de la proposition anglaise de EX-10.15 |
| F6 | contrôle 8 réussi | `␣;␣` suivi de la proposition française de EX-11.22 | `;␣` suivi de la proposition anglaise de EX-11.22 |
| F7 | au moins un contrôle `non_execute` | `␣; ce dossier ne prouve rien sur␣` suivi des éléments, joints par `, sur␣` et, devant le dernier, par `␣ni sur␣` | `; this dossier proves nothing about␣` suivi des éléments, joints par `,␣` et, devant le dernier, par `␣or␣` |
| F8 | toujours | `.` | `.` |

Valeurs de `{voisinage}` et `{neighbours}` :

| Cas | Français | Anglais |
|---|---|---|
| deux voisins | `chaîné à ses voisins seq {p} et {n}` | `chained to its neighbours seq {p} and {n}` |
| `next` nul | `chaîné à son voisin précédent seq {p} (le dossier ne fournit pas de suivant)` | `chained to its previous neighbour seq {p} (the dossier gives no next event)` |
| `previous` nul | `premier événement du journal, chaîné à son voisin suivant seq {n}` | `the first event of the journal, chained to its next neighbour seq {n}` |
| les deux nuls | `premier événement du journal, sans voisin dans le dossier` | `the first event of the journal, with no neighbour in the dossier` |

Valeurs de `{provenance}` (EX-3.6). Les clés employées sont `{cle_evenement}`
et `{cle_manifeste}`, une seule quand elles sont égales ; les clés des voisins
et des décisions n'en sont pas, même quand N-3 les compare. Chaque clé
employée a sa provenance, la plus forte dont la condition est remplie, dans
l'ordre de la table :

| Provenance | Condition, pour une clé | Français, toutes les clés de même provenance (pluriel / singulier) | Anglais | Une clé, cas mixte |
|---|---|---|---|---|
| `ancres` | N-3 a réussi et a comparé cette clé à celle du fichier d'ancres | `clés fournies par le fichier d'ancres` / `clé fournie par le fichier d'ancres` | `keys given by the anchors file` / `given by the anchors file` | `fournie par le fichier d'ancres` / `given by the anchors file` |
| `registre` | le contrôle 8 a réussi et R-10, réussie, prouve une inscription dont la clé Ed25519 est la `public_key` de cette clé | `clés inscrites au registre` / `clé inscrite au registre` | `keys registered in the registry` / `registered in the registry` | `inscrite au registre` / `registered in the registry` |
| `dossier` | sinon | `clés déclarées par le dossier` / `clé déclarée par le dossier` | `keys declared by the dossier` / `declared by the dossier` | `déclarée par le dossier` / `declared by the dossier` |

Quand toutes les clés employées ont la même provenance, `{provenance}` est le
texte des colonnes « Français » et « Anglais », au pluriel pour deux clés, au
singulier pour une. Quand les deux clés ont des provenances différentes,
`{provenance}` est `clé {cle_evenement} {p₁}, clé {cle_manifeste} {p₂}`
(anglais `key {cle_evenement} {p₁}, key {cle_manifeste} {p₂}`), `{p₁}` et
`{p₂}` étant les textes de la dernière colonne. Le rapport porte la provenance
de chaque clé (`facts.recorder_keys`, section 8.6) et, pour l'ensemble,
`mixte` dans ce cas.

Éléments de F7, dans cet ordre :

| Condition | Français | Anglais |
|---|---|---|
| contrôles 4 et 5 non réussis | `sa date (contrôles 4 et 5)` | `its date (controls 4 and 5)` |
| contrôle 4 seul non réussi | `un horodatage par une autorité (contrôle 4)` | `a time-stamp by an authority (control 4)` |
| contrôle 5 seul non réussi | `un ancrage dans Bitcoin (contrôle 5)` | `an anchoring in Bitcoin (control 5)` |
| contrôle 7 non réussi | `une approbation (contrôle 7)` | `an approval (control 7)` |
| contrôle 8 non réussi | `son inscription au registre (contrôle 8)` | `its registration in the registry (control 8)` |

`{approbateurs}` : les adresses de `approval.approvers`, dans leur ordre,
jointes par `,␣` et, devant la dernière, par `␣et␣` (anglais `␣and␣`) ;
`{nb} signatures` s'écrit `1 signature` quand `{nb}` vaut 1.

**EX-6.9** Pour un verdict `invalide`, l'énoncé est formé de trois
fragments, le deuxième seulement si `blocking_unexecuted` n'est pas vide :

| Fragment | Français | Anglais |
|---|---|---|
| I0 | `Dossier invalide : vérification(s) en échec : {ids}` | `Invalid dossier: failed check(s): {ids}` |
| I1 | `␣; vérification(s) non exécutée(s) sans raison admise : {ids}` | `; check(s) not run without an admitted reason: {ids}` |
| I2 | `␣; le vérificateur n'affirme rien sur cet événement.` | `; the verifier asserts nothing about this event.` |

Les identifiants sont ceux de `failed_checks` et de `blocking_unexecuted`,
joints par `,␣`. Quand `failed_checks` est vide, I0 devient `Dossier
invalide : vérification(s) non exécutée(s) sans raison admise : {ids}`
(`Invalid dossier: check(s) not run without an admitted reason: {ids}`) et
I1 est omis.

**EX-6.10** Une entrée inutilisable (code 2) n'a pas d'énoncé.

**EX-6.11** Formats des valeurs de l'énoncé et du rapport :

- hachages, identifiants de 32 octets et adresses : hexadécimal minuscule
  complet, préfixe `0x` (CT-1 §3) ; le hachage d'un bloc Bitcoin est écrit
  dans l'ordre d'affichage usuel, octets inversés par rapport à la sortie de
  dSHA, qui est l'ordre où ce hachage figure dans `hashPrevBlock` de l'en-tête
  suivant (R2-F28, R2-F44, R2-F48) ;
- instants : RFC 3339 en UTC, `AAAA-MM-JJThh:mm:ssZ`, avec une fraction de
  seconde seulement si elle est non nulle, sans zéro final ; `{period_start}`
  et `{period_end}` sont les secondes UNIX du manifeste écrites ainsi ;
- entiers : décimal sans séparateur ;
- `{seq}`, `{hash}`, `{org_id}`, `{journal_id}` : ceux de `evenement.json` ;
  `{period_hash}` : `periodHash` recalculé ; `{p}`, `{n}` : `seq` des voisins ;
- `{cle_evenement}` : `recorder_key_id` de l'événement prouvé ;
  `{cle_manifeste}` : celui de `manifeste.sig` ;
- `{decision}` : `approval.decision` de l'événement prouvé (`approuve`,
  `refuse` ou `expire`, CT-1 §5) ;
- `{nb}` : nombre d'adresses de `approval.approvers` ; `{required}` et
  `{size}` : `approval.threshold.required` et `approval.threshold.size`,
  déclarés par le dossier (A-3 vérifie que `size` est le nombre de membres du
  jeu déclaré) ;
- les valeurs des propositions F4, F5 et F6 sont celles que les sections 9.7,
  10.7 et 11.6 rapportent, aux formats de ces sections.

### 6.6 Borne

**EX-6.12** Quand au moins un des huit contrôles est `non_execute`, le rapport
porte une borne (CT-1 §11.3), dans la langue de sortie : `verdict borné :␣`
(anglais `bounded verdict:␣`) suivi, pour chaque contrôle non exécuté, dans
l'ordre de 1 à 8, de `contrôle {N} non exécuté ({raison})` (anglais
`control {N} not run ({raison})`), joints par `,␣`. Sinon la borne est nulle.
Ce que la borne laisse sans preuve est dit par le fragment F7 de l'énoncé.

La raison que donne la borne est un code de la liste fermée de 6.2. Son nom
ne suffit pas toujours à dire la cause. La table 6.2 en donne la portée. La
puce « La borne » de 7.1 dit les cas que ce nom ne laisse pas deviner, et
comment les lire.

### 6.7 Faits rapportés

**EX-6.13** Le rapport JSON ne range sous `facts` que des valeurs établies par
des contrôles réussis : `recorder_keys` est nul si le contrôle 6 n'a pas
réussi, `approval` si le 7, `timestamp` si le 4, `bitcoin` si le 5,
`registry` si le 8. Les champs de `timestamp`, `bitcoin` et `registry` sont
ceux qu'exigent EX-9.19, EX-10.14 et EX-11.21. Une valeur lue dans le dossier
sans être prouvée n'y figure jamais ; les valeurs qu'une vérification en
échec a lues figurent dans son `detail`, comme diagnostic. Les champs `event`, `org_id`, `journal_id` et `period` servent
à désigner l'événement ; ils sont lus dans `evenement.json` et
`manifeste.json` quand ceux-ci sont exploitables, et ne sont pas des faits
prouvés quand le verdict est `invalide` (comme dans CT-1, rien n'est repris de
l'index à la place d'une partie inexploitable). Dans un rapport `invalide`,
`facts` garde, pour situer l'écart, les valeurs des contrôles réussis ; ce ne
sont pas des affirmations (7.4). Un programme qui lit le rapport NE DOIT
employer `facts` que si `verdict` vaut `valide` ou `incomplet`.

**EX-6.15** Les avertissements (`warnings`) sont rapportés dans l'ordre du
rapport de la vérification qui les lève (son `check`, ordre de la section
5.2), puis par identifiant (`AV-T-1` avant `AV-T-2`…), puis, pour un même
identifiant et une même vérification, dans l'ordre de leur objet : attestations
dans l'ordre du fichier `.ots`, CRL dans l'ordre du fichier d'ancres puis du
champ `crls` du jeton, extensions dans l'ordre du jeton, certificats et
entrées dans l'ordre de leur partie. Deux implémentations conformes rendent
donc la même liste, dans le même ordre (V-1, V-8).

### 6.8 Compatibilité avec les dossiers CT-1

**EX-6.14** Sur un dossier CT-1, sans fichier d'ancres ou avec un fichier
d'ancres conforme qui ne donne, pour l'organisation et le journal du dossier,
aucune clé d'enregistreur ou les mêmes clés que `cles.json`, le vérificateur
rend le même code de retour que la version CT-1 de
`scripts/verify/dossier.mjs`, et `failed_checks` est égal, dans le même ordre,
à la liste `controles_en_echec` de l'`attendu.json` du dossier. Les
contrôles 4, 5 et 8 y sont `non_execute`, raison `hors_perimetre_version` ; le
contrôle 7 l'est avec la raison `partie_absente` quand l'événement ne porte
pas d'approbation. Le libellé des lignes du rapport lisible change (section
8.5) et la sortie JSON de la version CT-1, qui n'avait pas de schéma, est
remplacée par le rapport de la section 8.6 ; le code de retour et la liste
des vérifications en échec ne changent pas. Un fichier d'ancres non conforme
rend le code 2 (EX-4.10) ; un fichier d'ancres qui donne, pour le triplet
(`org_id`, `journal_id`, `key_id`) d'une clé de `cles.json` qui signe un
événement du dossier ou le manifeste, une autre `public_key` fait échouer N-3
(EX-12.4), donc le contrôle 6, et rend un dossier CT-1 invalide : c'est le
comportement voulu, le dossier contredisant alors une ancre du réviseur. Une
clé dont le `key_id` ne figure pas dans le fichier d'ancres n'est pas
comparée. Elle ne fait rien échouer, même si le fichier donne d'autres clés
pour ce journal, et garde la provenance `dossier` (EX-6.8).

### 6.9 Vérifications du verdict (V-)

Ces vérifications portent sur le rapport, pas sur le dossier : CT-9 les
exécute en comparant le rapport du vérificateur à l'`attendu.json` de chaque
vecteur. Elles ne figurent pas dans `checks`.

| Id | Règle | Exigences |
|---|---|---|
| V-1 | Chaque vérification que la section 5 fait figurer au rapport (EX-5.6) figure une fois dans `checks`, dans l'ordre de la section 5.2, avec un statut et, si elle est `non_execute`, une raison de la liste fermée et `admitted` conforme à la table 6.2. | EX-5.6, EX-6.1, EX-6.2, EX-6.3 |
| V-2 | Le statut et la raison de chacun des huit contrôles suivent EX-6.4 et EX-6.5. | EX-6.4, EX-6.5, EX-6.6 |
| V-3 | Le verdict, `failed_checks` et `blocking_unexecuted` suivent EX-6.7. | EX-6.7 |
| V-4 | Le code de retour et `exit_code` correspondent au verdict (section 8.3). | EX-8.4 |
| V-5 | L'énoncé, dans les deux langues, est égal octet pour octet à celui que construisent les fragments de la section 6.5, et la borne à celle de EX-6.12. | EX-6.8 à EX-6.12 |
| V-6 | Aucun contrôle n'est `reussi` sans que ses parties requises soient présentes, ses ancres fournies et ses vérifications exécutées et réussies (sauf `piece_hors_dossier` et les vérifications sans effet sur le statut, EX-6.4) ; `facts` ne contient que des valeurs de contrôles réussis. | EX-6.6, EX-6.13 |
| V-7 | Sur chacun des quarante dossiers de `spec/vecteurs/ct-1/dossiers`, le code de retour et `failed_checks` sont ceux de leur `attendu.json`. | EX-6.14 |
| V-8 | Deux exécutions sur les mêmes entrées donnent le même rapport JSON, octet pour octet, aux chemins de `inputs` près ; une exécution sans réseau (`unshare -n`) donne le même rapport qu'une exécution avec réseau. | EX-3.2, EX-3.3, EX-8.7 |

## 7. Ce que le vérificateur prouve et ne prouve pas

Cette section se lit seule. Elle dit ce qu'un réviseur peut affirmer après
une vérification, et ce qu'il ne peut pas affirmer. Chaque ligne est une
phrase qu'il peut répéter telle quelle pour dire ce que vaut l'énoncé, qui
reste la seule phrase du rapport à citer (7.1). Les identifiants entre
parenthèses (T-10, EX-9.13, H3, A-1…) renvoient au détail, et chaque phrase
se comprend sans eux. Les vérifications D-, E-, C-, M-, P- et A- sont
celles de CT-1 §11.4 ; la table 5.1 dit ce que chaque contrôle en tire.

« Prouver » a ici un sens précis : établir, par un calcul que n'importe qui
peut refaire hors ligne, à partir du dossier et du fichier d'ancres du
réviseur, sous les hypothèses de la section 7.8. Refaire le calcul ne dit pas
que ses règles sont les bonnes. Celles du contrôle 8 viennent du code privé
de noorcore et d'expériences sur le réseau de développement. Un réviseur qui
n'a pas accès à ce code les tient de NOORTRACE (7.8, qui en donne la liste).
Un fait externe que l'annexe B dit « non recoupable » repose sur la note,
R1 à R4, qui le rapporte. Une preuve vaut pour l'événement nommé dans
l'énoncé, avec les ancres nommées, et pour rien d'autre.

**EX-7.1** Aucune sortie du vérificateur (énoncé, borne, résumé de contrôle,
détail de vérification, texte d'aide) NE DOIT affirmer une propriété que
cette section range parmi ce qui n'est pas prouvé.

### 7.1 Ce qu'il faut lire dans un rapport

- Le verdict : `valide`, `invalide`, `incomplet`, ou aucun verdict (code 2).
  « Valide » ne veut pas dire que les huit contrôles ont réussi. Il veut dire
  que rien n'a échoué et que toute non-exécution, d'un contrôle ou d'une
  vérification, a une raison admise (6.4). Un dossier sans aucune preuve de
  date peut être « valide », code 0 (exemple du dossier CT-1 de 8.5). Avant
  de conclure, lisez la borne (ligne `Borne`, champ `bound` ; puce
  « La borne » ci-dessous) et la fin de l'énoncé (« ce dossier ne prouve
  rien sur … »). Ou relancez le vérificateur avec `--exiger` et les
  contrôles dont vous avez besoin : si l'un d'eux n'a pas réussi, le verdict
  est « incomplet », code 3, sauf si le dossier est invalide (7.5).
- Le statut de chacun des huit contrôles : réussi, échoué, ou non exécuté avec
  sa raison.
- La borne (ligne `Borne`, champ `bound`) : elle nomme chaque contrôle non
  exécuté et sa raison (EX-6.12). La raison que donne la borne est un code
  de la liste fermée de 6.2, et son nom ne suffit pas à dire la cause.
  `ancre_absente` couvre aussi un fichier d'en-têtes Bitcoin fourni qui ne
  contient pas la hauteur de votre point de contrôle, ne contient celle
  d'aucun bloc attesté, ne couvre pas la fenêtre de difficulté ou n'atteint
  pas `min_confirmations` (EX-10.9, règles 3 et 5 ; O-4 ; O-6).
  `partie_absente` couvre aussi une `preuve.ots` présente qui n'a que des
  attestations en attente. Pour le contrôle 4, `ancre_absente` couvre aussi
  un certificat de l'unité qui n'est ni dans le jeton ni dans votre fichier
  d'ancres (T-4). L'exportateur peut l'avoir retiré du jeton, ce qui
  soustrait le jeton à T-7 (7.3). Ajoutez ce certificat à vos
  `intermediates` pour que le jeton soit examiné. `hors_perimetre_version`
  sur une partie absente ne repose que sur l'index, que personne ne signe
  (7.3). Le détail des vérifications du contrôle dit quelle est la cause :
  pour le contrôle 4, T-4, T-7, ou T-10 quand un certificat du chemin n'a
  ni liste de révocation retenue ni déclaration de non-révocation de date
  postérieure ou égale à `genTime` (EX-9.16) ; pour le contrôle 5,
  O-4 à O-7 (7.3).
- Les avertissements (`AV-…`) : ils ne changent aucun statut. Un statut
  « réussi » dit que la règle tient, pas ce qu'elle vaut (EX-6.1). AV-O-3
  signale que la chaîne d'en-têtes a été examinée sur `regtest` (O-5) : un
  contrôle 5 réussi sur ce réseau ne prouve rien. L'énoncé le répète par
  « (réseau d'essai, sans valeur probante) », et le résumé du contrôle 5 par
  « (réseau d'essai) ». Le réseau `regtest` est la seule donnée de test
  signalée. Une autorité d'horodatage, un registre ou un jeu de validateurs
  de test que votre fichier d'ancres déclare ne lèvent aucun avertissement.
  L'énoncé en parle sans réserve (puce « L'énoncé »). L'exemple de 8.5
  emploie de telles ancres : son verdict n'est pas probant. Que vos ancres
  ne soient pas des ancres de test relève de H3.
- L'énoncé : c'est la seule phrase du rapport à citer comme affirmation.
  Citez-la toujours avec les identifiants qui disent sur quoi elle porte, et
  qui ne sont pas des affirmations : la ligne `Index` (SHA-256 de
  `dossier.json`), la ligne `Ancres` (SHA-256 de votre fichier d'ancres), les
  lignes `En-têtes`, `Pièces` et `2e manifeste` quand ces entrées sont
  fournies (`inputs` ; la ligne `Pièces` ne donne que le répertoire et le
  nombre de pièces lues), et le nom de qui a préparé votre fichier d'ancres.
  Ce nom est son champ `prepared_by`, que le rapport ne reprend pas :
  lisez-le dans le fichier dont la ligne `Ancres` donne l'empreinte. Sans
  ces identifiants, son lecteur ne peut ni retrouver les ancres avec
  lesquelles elle vaut, ni voir si ce sont des ancres de test. L'énoncé ne
  porte ni l'empreinte de votre fichier d'ancres ni son auteur. Il nomme
  l'autorité d'horodatage et la source du jeu de validateurs par les
  libellés de votre fichier (`name`, `source`), que le vérificateur ne
  contrôle pas. Il ne vaut qu'avec vos ancres (H3). Une autorité
  d'horodatage, un registre ou un jeu de validateurs de test y paraissent
  comme les autres, et `--exiger 5` est satisfait sur `regtest` (7.5). Les
  résumés de contrôle, les détails et les avertissements servent à le lire,
  non à être cités comme affirmations. Il dit ce qui est prouvé. Il
  rapporte aussi, chacune avec sa qualification, des heures qui ne le sont
  pas (« heure inscrite par le mineur », « borne sous hypothèse », « heure
  déclarée par le bloc »). Puis il dit ce qui n'est pas prouvé. Deux de ses
  expressions se lisent toujours avec 7.2 : « inclus dans la période du …
  au … close par le manifeste », et « le contrat `PeriodRegistry` 0x… »
  avec « `AttestationRegistry` 0x… ». Quand vous le citez à un lecteur non
  spécialiste, joignez-lui ces deux lectures. Aucune heure du registre n'est
  comparée aux dates de la période : une heure déclarée antérieure à la
  période n'est pas signalée. Les deux valeurs sont déclarées : l'heure du
  bloc par son proposant (R3 F8), les bornes de la période par
  l'enregistreur. Leur écart ne contredit aucune vérification, et leur
  accord ne prouverait aucune date. AV-T-4, lui, compare `ts` à `genTime`
  augmenté de la précision du jeton, instant que l'autorité d'horodatage
  signe et dont le contrôle 4, quand il réussit, tire sa date. Un écart
  entre l'heure du registre et la période peut venir de l'horloge du
  proposant comme de bornes fausses. Si cela vous importe, comparez
  vous-même `facts.registry.entries[].block_time` à `period`.

### 7.2 Verdict « valide », les huit contrôles réussis

Le vérificateur prouve :

- L'événement du dossier est exactement celui dont l'empreinte est dans la
  racine de sa période (contrôles 1 et 3).
- Il respecte le format de CT-1 (contrôle 1).
- Il est relié par leurs empreintes aux voisins que le dossier fournit : le
  précédent et le suivant, ou le seul des deux que le dossier contient
  (contrôle 2). Le dossier du premier événement du journal peut n'en
  fournir aucun. L'énoncé dit lequel de ces cas s'applique (6.5). « Le
  dossier ne fournit pas de suivant » ne dit pas qu'aucun événement n'a
  suivi : le vérificateur ne peut pas le savoir (C-1). Un voisin peut
  appartenir à la période adjacente quand l'événement est le premier ou le
  dernier de la sienne (P-3).
- La clé d'enregistreur nommée a signé l'événement, ses voisins et le
  manifeste de la période (contrôle 6).
- Les adresses nommées ont signé la décision liée à l'événement, et elles
  sont au moins aussi nombreuses que le seuil déclaré (contrôle 7). L'énoncé
  dit laquelle : une approbation (« a été approuvé par »), un refus (« porte
  un refus signé par ») ; une demande expirée (« porte une demande
  d'approbation expirée sans signature ») ne porte aucune signature.
- Le manifeste de la période existait sous cette forme au plus tard à
  l'instant du jeton augmenté de sa précision (`genTime` + `accuracy`), selon
  l'autorité d'horodatage nommée. Le certificat de l'unité qui a signé le
  jeton mène à une autorité de votre fichier d'ancres ; chaque certificat de
  ce chemin, sauf celui de l'autorité elle-même, était valide à cet instant et
  n'était pas révoqué selon une liste de révocation dont la signature a été
  vérifiée (venue de votre fichier d'ancres ou du champ `crls` du jeton), ou
  selon une déclaration de votre fichier d'ancres (T-10 ; le détail de T-10
  dit laquelle) ; le certificat de l'autorité n'était révoqué par aucune
  liste de révocation de votre fichier d'ancres (contrôle 4). Le
  vérificateur n'impose aucune date maximale à la liste ou à la déclaration
  qui prouve la non-révocation d'un certificat du chemin. Il suffit que sa
  date (`thisUpdate` d'une liste, `not_revoked_at` d'une déclaration) soit
  postérieure ou égale à `genTime` (EX-9.16). Une AC peut retirer de ses
  listes l'entrée d'un certificat révoqué dès que cette entrée a figuré sur
  une liste régulière émise après la fin de validité du certificat
  (RFC 5280 §3.3, https://www.rfc-editor.org/rfc/rfc5280.txt, copie du
  digest R1). Une liste émise après cette fin de validité peut donc ne plus
  porter un certificat pourtant révoqué. « Non révoqué » veut alors
  seulement dire « absent de cette liste », ou, pour une déclaration,
  « déclaré non révoqué par votre fichier d'ancres à cet instant ». Aucun
  avertissement ne signale une liste ou une déclaration tardive. Le rapport
  donne la date de chaque preuve (`facts.timestamp.revocation[].issued_at`) :
  comparez-la à `gen_time` et à la fin de validité (`notAfter`) du
  certificat que désigne `certificate_sha256`. CT-5 capture ces listes peu
  après `genTime` (EX-13.12), mais le vérificateur ne contrôle pas cet
  écart. Quand le certificat que votre fichier d'ancres donne pour
  l'autorité est celui de l'unité elle-même, et non celui d'une AC au-dessus
  d'elle (unité
  « épinglée », section 2), ce certificat est aussi celui qui a signé le
  jeton, et il était dans ses dates à `genTime` (EX-9.13). Si le jeton ne
  porte pas de précision, il ne prouve aucune date limite chiffrée : l'énoncé
  donne `genTime` « à la précision près de la politique …, que le jeton
  n'indique pas » (EX-9.20). Cette précision se lit dans la politique de
  l'autorité, hors du vérificateur. Si le jeton en porte une, elle peut aller
  jusqu'à une journée plus 999 ms et 999 µs, soit 86 400,999999 s (T-9,
  EX-9.15 règle 2). La date de l'énoncé l'inclut déjà, et le rapport donne
  `accuracy`.
- Le même manifeste existait avant la création du bloc Bitcoin nommé. Ce bloc
  est relié à votre point de contrôle par la chaîne d'en-têtes fournie, dont
  la preuve de travail a été recalculée au-dessus du point de contrôle
  (contrôle 5). Sur un réseau d'essai (`regtest`, avertissement AV-O-3),
  cette ligne ne vaut rien. « Sous k blocs » (k confirmations) compte le
  bloc attesté lui-même : k − 1 blocs le suivent dans la chaîne fournie
  (k = t − h + 1, EX-10.10). Le travail n'est
  recalculé que pour les en-têtes situés au-dessus de votre point de
  contrôle. Ceux qui sont à sa hauteur ou en dessous sont tenus par le seul
  chaînage des hachages jusqu'à lui (EX-10.9). Si le bloc attesté est à la
  hauteur de votre point de contrôle ou en dessous, il vaut donc ce que vaut
  votre point de contrôle (H3), non un travail. Parmi les k blocs, seuls ceux
  qui sont au-dessus du point de contrôle portent alors un travail recalculé
  (`cumulative_work`, EX-10.14). C'est ainsi que se lit « dont le travail se
  rattache au point de contrôle ». Cas limite : un fichier d'en-têtes qui
  s'arrête à votre point de contrôle (t = c, ce que EX-10.9 admet) ne porte
  aucun travail recalculé. `cumulative_work` vaut alors 0, et la profondeur
  que vous exigez (`min_confirmations`) est atteinte par des blocs tenus par
  le seul chaînage. Ce que la ligne prouve tient encore, parce que le bloc
  attesté est votre point de contrôle ou l'un de ses ancêtres. Mais elle vaut
  alors entièrement ce que vaut votre point de contrôle (H3), et k ne mesure
  aucun travail. Aucun avertissement ne le signale : lisez `cumulative_work`
  (`facts.bitcoin`). L'énoncé n'affirme pas pour autant un travail qui n'a
  pas été recalculé (EX-7.1) : « dont le travail se rattache » se lit comme
  ci-dessus.
- Donc l'événement existait sous cette forme au plus tard à cet instant, et
  avant la création de ce bloc : son empreinte est dans la racine, et la
  racine est dans le manifeste (contrôles 1, 3, 4 et 5).
- Une version modifiée de l'événement, d'un autre événement de la période ou
  du manifeste ne passerait plus les contrôles 4 et 5 avec ce jeton et cette
  preuve, car toute modification change la racine ou le manifeste, donc
  `periodHash`. Une modification de cet événement ou du manifeste se verrait
  dans ce dossier. Celle d'un autre événement de la période se verrait dans
  le dossier de cet autre événement, dont la feuille ne remonterait plus à
  la racine horodatée. Dans celui-ci, elle ne se verrait que pour le voisin
  précédent, dont l'empreinte est le `prev_hash` de l'événement
  (contrôle 2). Un voisin suivant réécrit et signé de nouveau par qui tient
  la clé de l'enregistreur peut encore passer les huit contrôles.
- Un quorum des validateurs de votre fichier d'ancres a signé les blocs du
  registre où les contrats de votre fichier d'ancres ont enregistré la clôture
  de la période (`periodHash`) et son ancre (`anchorFingerprint`)
  (contrôle 8).
- Dans l'énoncé, « le contrat `PeriodRegistry` 0x… » et
  « `AttestationRegistry` 0x… » désignent les adresses que votre fichier
  d'ancres donne pour les rôles `period_registry` et `attestation_registry`
  (R-8). Que le code à ces adresses soit celui de ces contrats est
  l'hypothèse H7, non vérifiée. Sans elle, l'énoncé établit seulement que ces
  adresses ont émis les événements `PeriodSubmitted` et `Anchored`.
- Quand l'énoncé le dit (« clé de chaîne inscrite au bloc … »), la clé de
  chaîne qui a signé l'ancre est celle sous laquelle la clé du manifeste a été
  inscrite au registre (contrôle 8, R-10).
- Quand l'énoncé le dit (« que le réviseur tient pour la clé de chaîne
  de … »), cette clé de chaîne est celle que votre fichier d'ancres donne
  pour la clé du manifeste (contrôle 8, N-4).

Le vérificateur ne prouve pas :

- Que l'événement a eu lieu à l'heure `ts` qu'il porte. `ts` vient de
  l'horloge de l'enregistreur.
- Que l'événement n'existait pas avant une date donnée. Seule une date limite
  est prouvée : « au plus tard ».
- Que l'événement a eu lieu entre les deux instants « du … au … » de
  l'énoncé. Ce sont les bornes `period_start` et `period_end` que le
  manifeste déclare sous la signature de la clé d'enregistreur. « Inclus dans
  la période … close par le manifeste … » veut dire que l'événement est une
  feuille de l'arbre de ce manifeste, et que son `ts` déclaré tombe entre ces
  bornes (contrôle 3, P-2). Cela ne date pas l'événement : `ts` et les bornes
  sont des déclarations de l'enregistreur. Les seules limites de temps
  prouvées sont celles des contrôles 4 et 5, quand ils réussissent.
- Que l'agent a fait ce que l'événement décrit, ni que l'outil a produit les
  effets déclarés. `effects` est une déclaration de l'enregistreur (CT-1 §15).
- Qui a lancé l'agent, et pour le compte de qui. `delegation` est une
  déclaration de l'enregistreur.
- Quelle entreprise désigne l'organisation. `org_id` est un identifiant de
  32 octets ; le relier à une entreprise se fait hors du vérificateur.
- Que tous les actes de l'agent ont été journalisés. Un acte qui ne passe pas
  par l'enregistreur n'y figure pas (CT-2 §21).
- Que l'enregistreur était sain avant l'instant du jeton. Qui tenait sa clé a
  pu signer de faux événements dans la période. Jusqu'à l'instant du jeton
  (et, pour le contrôle 5, jusqu'à la création du bloc), il a aussi pu
  réécrire et signer de nouveau toute la période (3.4). Le vérificateur ne
  compare pas l'instant du jeton à la fin de la période : un jeton obtenu
  longtemps après elle allonge d'autant cette fenêtre, sans échec ni
  avertissement. Pour mesurer cet écart, comparez `upper_bound`
  (`facts.timestamp`), ou `gen_time` quand `upper_bound` est nul (jeton sans
  précision), à `period_end` (`period`). Qui tient cette clé dépend de sa
  classe de garde (CT-2 §11.2). L'opérateur, c'est-à-dire le client qui
  exploite l'agent et l'enregistreur et qui exporte le dossier, peut en
  disposer dans les classes C et D (3.4). Dans les classes A et B, il ne
  peut pas l'exporter, mais il garde l'usage du signataire que son
  enregistreur emploie (CT-2 EX-11.4, §11.5). Les contrôles 1, 2, 3 et 6 ne
  vous protègent donc pas de lui, quelle que soit la classe, avant l'instant
  du jeton (ou, pour le contrôle 5, avant la création du bloc). La classe de
  garde n'est ni dans le dossier, ni dans le rapport, ni dans l'énoncé, et le
  vérificateur ne la contrôle pas. Elle se constate hors de lui, par les
  mêmes voies que la clé : le procès-verbal d'inscription de la clé (CT-2
  EX-11.13) et la cérémonie des clés (CT-7) (12.5, ligne `recorders`). Ce
  n'est pas une hypothèse des phrases que le vérificateur prouve : elles
  restent vraies quel que soit le détenteur de la clé. La classe dit
  seulement qui, outre l'opérateur, peut se servir de la clé. Elle dit aussi
  si la clé peut être copiée, et donc servir encore après le retrait de son
  accès (CT-2 §18.5). C'est pourquoi elle ne figure pas en 7.8.
- Que la clé d'enregistreur appartient à l'organisation, au-delà de ce que
  disent les mentions de l'énoncé. « Fournie par le fichier d'ancres » :
  c'est la clé que vous avez déclarée pour cette organisation, ce journal et
  ce `key_id` (H3). « Inscrite au registre » : un événement
  `RecorderRegistered` pour cette organisation, ce journal et cette clé a été
  émis à l'adresse `recorder_registry` de votre fichier d'ancres, dans un bloc
  signé par un quorum de votre jeu de validateurs (R-8, R-10). La mention
  désigne cet événement émis, pas une inscription dont le vérificateur aurait
  contrôlé l'autorisation. Que le contrat n'admette que les inscriptions
  autorisées par l'organisation dépend du code déployé à cette adresse, que
  le vérificateur ne contrôle pas (H7). Rien
  n'est prouvé ni sur la date de l'inscription ni sur une révocation de la clé
  après son inscription (11.8). Sans l'une de ces deux mentions, l'énoncé dit
  « déclarée par le dossier ». Votre fichier d'ancres ne confirme une clé que
  sous son `key_id` (N-3). Une clé que le dossier nomme sous un `key_id`
  absent de votre fichier n'est pas comparée, même si votre fichier donne
  d'autres clés pour ce journal. Ce n'est pas un échec. L'énoncé la dit alors
  « déclarée par le dossier », ou « inscrite au registre » si le contrôle 8
  la confirme. Il en va de même pour la clé de chaîne (N-4, `key_id` du
  manifeste). Le vérificateur ne lit jamais votre fichier comme la liste
  fermée des clés d'un journal. Son format ne permet pas de dire qu'une
  liste est complète (12.2). Une clé que votre fichier ne nomme pas n'y est
  ni confirmée ni contredite. Ce qui vous protège est la provenance, que
  l'énoncé écrit pour chaque clé employée (6.5). Si vous tenez votre liste
  pour complète, une clé employée que l'énoncé ne dit pas fournie par le
  fichier d'ancres est une clé dont votre fichier ne donne pas le `key_id`
  pour cette organisation et ce journal. `--exiger 6` n'exige pas la
  provenance « fournie par le fichier d'ancres » : lisez-la dans l'énoncé ou
  dans `facts.recorder_keys`.
- Que les approbateurs nommés avaient le droit d'approuver. Leur jeu est
  déclaré par le dossier ; il n'est pas comparé au jeu inscrit au registre.
- Que les personnes qui tiennent ces adresses ont lu ce qu'elles
  approuvaient.
- Que l'autorité d'horodatage est qualifiée. Quand l'énoncé dit
  « horodatage qualifié … selon le réviseur », c'est votre fichier d'ancres
  qui le déclare ; le vérificateur ne lit aucune liste de confiance. La norme le dit aussi : la mention « qualifié » dans un jeton
  n'est qu'une prétention de l'autorité (ETSI EN 319 421 §8.1, note 2,
  R1 F3.16).
- Que l'heure du jeton est juste si l'autorité ment. Seul le bloc Bitcoin
  donne une limite indépendante d'elle.
- Que l'autorité de votre fichier d'ancres était elle-même valide et non
  révoquée à l'instant du jeton : seuls sa clé et son nom servent (EX-9.13),
  et sa révocation n'est vue que si une liste de révocation de votre fichier
  d'ancres la porte (EX-9.16). C'est à vous de le vérifier quand vous la
  choisissez (12.5). Si votre autorité est l'unité elle-même, épinglée, ses
  dates sont toutefois comparées à l'instant du jeton (EX-9.13).
- L'heure précise du bloc Bitcoin. L'heure de son en-tête est choisie par le
  mineur ; le protocole n'en prouve pas la précision (R2-F37 à R2-F39). La
  « borne sous hypothèse » de l'énoncé n'est pas prouvée non plus. Elle
  suppose qu'au moins six des onze blocs qui suivent portent l'heure honnête
  de leur création, à la dérive d'horloge près. Cette hypothèse est déduite
  par cette spécification (EX-10.13).
- Que le bloc Bitcoin est dans la chaîne la plus longue d'aujourd'hui. Il est
  relié à votre point de contrôle par la chaîne d'en-têtes fournie, sans
  comparaison avec le réseau.
- Une date tirée du registre. L'horodatage d'un bloc du registre est choisi
  par son proposant (R3 F8).
- Que les blocs du registre sont authentiques si au moins un quorum de ses
  validateurs s'est entendu pour en signer de faux.
- Que le code exécuté aux adresses des contrats est celui publié dans ce
  dépôt (non vérifié, R3 NV7).
- Qu'aucun autre manifeste n'a été produit pour la même heure. Ni, par le
  contrôle 8, qu'aucune autre clôture de la même période n'a été inscrite :
  que le contrat la refuse relève de H7, et qu'un faux bloc ne la fasse pas
  passer, de H6 (3.4).
- Que la période suit sans trou la période précédente, sauf si le manifeste
  précédent a été fourni (`--second-manifeste`) et que P-5 a vérifié la
  continuité : `prev_period_hash`, couvert par la signature du manifeste
  prouvé, désigne alors ce manifeste. Un manifeste suivant fourni à part ne
  prouve rien : n'importe qui peut en écrire un dont `prev_period_hash` vaut
  `periodHash`, et sa signature n'est pas vérifiée.
- Le contenu des autres événements de la période : la racine les couvre, mais
  ils ne sont ni montrés ni vérifiés. Les voisins et les décisions
  d'approbation que le dossier fournit font exception. Leur forme, leur
  empreinte et leurs signatures sont vérifiées (contrôles 1, 2, 6 et 7).
  Leur place dans la racine horodatée n'est pas prouvée. Seul le voisin
  précédent est engagé par l'événement, dont le `prev_hash` est son
  empreinte (C-2).
- Le contenu des pièces (arguments, résultats, documents), sauf celui des
  pièces fournies à part, dont l'empreinte a été vérifiée (E-6).
- Que la conclusion a une valeur probante quand vos ancres sont des ancres
  de test : seul `regtest` est signalé (AV-O-3, 7.1).

### 7.3 Verdict « valide », avec des contrôles non exécutés

- Le vérificateur prouve exactement ce que disent les fragments de l'énoncé,
  et rien de plus.
- Un contrôle non exécuté ne prouve rien, ni pour ni contre le dossier.
- Une vérification non exécutée à l'intérieur d'un contrôle réussi (A-4,
  événement de demande hors du dossier ; T-11, aucun statut qualifié
  déclaré ; R-3, `validateurs.json` absent ; R-10, aucune inscription jointe ;
  N-3, votre fichier d'ancres donne des clés pour l'organisation et le
  journal du dossier, mais aucune sous le `key_id` d'une clé qui signe un
  événement du dossier ou le manifeste) ne retire rien à ce que le contrôle
  prouve. L'énoncé ne dit simplement pas ce qu'elle aurait établi.
- Contrôles 4 et 5 non exécutés : rien n'est prouvé sur la date. L'événement a
  pu être écrit ou réécrit à tout moment avant la vérification, par quiconque
  tenait la clé de l'enregistreur.
- Contrôle 4 seul non exécuté : la seule limite de temps vient de Bitcoin.
  Aucun horodatage par une autorité n'est prouvé, ni donc aucun effet
  juridique attaché à un horodatage qualifié.
- Contrôle 5 seul non exécuté : la seule limite de temps vient de l'autorité
  d'horodatage. Si elle ment, rien ne le révèle. Quand le contrôle 5 réussit,
  il ne le révèle pas davantage : il ajoute une seconde limite, indépendante
  d'elle, sans rien dire de l'heure du jeton.
- Contrôle 7 non exécuté parce que `approbations.json` est absent :
  l'événement ne déclare aucune approbation (`approval` nul), et rien n'est
  prouvé sur une approbation. Avec `--exiger 7` ou `--exiger tous`, un tel
  événement rend toujours `incomplet` (code 3) ; pour un événement sans
  approbation, exigez `1,2,3,4,5,6,8`. Un événement qui déclare une
  approbation sans `approbations.json` fait échouer A-1 (CT-1 §11.4 :
  `approbations.json` présent si et seulement si `approval` n'est pas nul) et
  rend le dossier invalide : l'exportateur ne peut pas retirer cette partie
  pour taire une décision.
- Contrôle 8 non exécuté : rien n'est prouvé sur l'inscription au registre.
- Raison `hors_perimetre_version` pour une partie absente : l'index, que
  l'exportateur écrit et que personne ne signe, déclare la partie absente
  « hors périmètre CT-1 ». Le verdict est borné comme pour `partie_absente`
  (CT-1 §11.3) ; rien ne prouve que le dossier ne pouvait pas être complété.
- Raison `hors_perimetre_version` pour une pièce présente : elle emploie une
  construction que cette version du vérificateur ne vérifie pas, par exemple
  une opération OpenTimestamps hors du profil de la section 10.
- Raison `ancre_absente` : il manque une donnée que vous pouvez fournir
  vous-même. Ce peut être une ancre de votre fichier (autorité, point de
  contrôle, `registry`), le certificat de l'unité d'horodatage quand le jeton
  ne le porte pas (à ajouter aux `intermediates`, T-4), une CRL ou une
  déclaration de non-révocation (T-10), ou un fichier d'en-têtes Bitcoin qui
  contient votre point de contrôle (EX-10.9, règle 3), couvre la fenêtre de
  difficulté (règle 5) et atteint `min_confirmations` (O-6), que vous pouvez
  produire depuis votre nœud. Avec elle, la même pièce pourrait réussir ou
  échouer.
- Contrôle 5 non exécuté, raison `partie_absente`, alors que `preuve.ots` est
  présente : ou bien la preuve n'est pas encore reliée à un bloc Bitcoin, elle
  ne porte que des attestations en attente, et une mise à niveau par
  l'exportateur (CT-5) le permettrait ; ou bien aucun fichier d'en-têtes
  Bitcoin n'a été fourni (`--entetes-bitcoin`). Le détail de O-5 et de O-7 dit
  lequel.
- Une absence peut venir d'un choix de l'exportateur, qui écrit l'index et
  assemble les pièces. Il peut déclarer absente une partie réservée requise
  par un contrôle (4.2, table 5.1), avec la raison « hors périmètre CT-1 »
  ou une autre. Il peut aussi retirer du jeton ses certificats, que la
  signature du jeton ne couvre pas (EX-9.12). Une pièce qui aurait fait
  échouer le dossier n'est alors plus examinée, ou seulement en partie : par
  exemple un jeton d'une autorité que votre fichier d'ancres ne contient pas
  (T-7). Le verdict passe ainsi d'« invalide » à « valide » borné. Rien de
  faux n'est affirmé : l'énoncé dit ce qui n'est pas prouvé. Pour qu'une
  absence ne passe pas pour un succès, exigez les contrôles dont vous avez
  besoin (`--exiger`, code 3). Ce remède ne vaut pas pour ce qui n'entre pas
  dans le statut d'un contrôle. Si la partie `validateurs.json` est déclarée
  absente, ou si `registre.json` ne contient aucune entrée `inscription`,
  R-3 ou R-10 ne s'exécute pas, sans effet sur le contrôle 8 (EX-11.20). Une
  telle pièce, qui aurait échoué, n'est plus examinée. Le contrôle 8 reste
  réussi : il n'entre pas dans la borne, et `--exiger 8` est satisfait. Le
  verdict passe alors d'« invalide » à « valide », sans que la borne le
  montre. Rien de ce que dit l'énoncé n'en devient faux. Sans inscription,
  il ne dit plus « inscrite au registre » ni « clé de chaîne inscrite au
  bloc … ». Repérez ces absences à la ligne « Parties absentes »
  (`absent_parts`), à l'avertissement AV-R-1 et à la provenance des clés
  (énoncé, `facts.recorder_keys`).

### 7.4 Verdict « invalide » (code 1)

- Au moins une vérification a échoué, ou n'a pas pu s'exécuter parce qu'une
  pièce dont elle dépend est inexploitable.
- Le vérificateur n'affirme alors rien sur l'événement. Les contrôles marqués
  réussis dans le même rapport aident à situer l'écart ; ce ne sont pas des
  affirmations.
- Il ne prouve pas que l'événement est faux. Il prouve que ce dossier ne
  l'établit pas : une erreur d'export et une falsification donnent le même
  verdict.
- La vérification en échec dit où le dossier contredit le calcul. Exemple :
  E-7 en échec, le hachage annoncé n'est pas celui de l'événement ; T-2 en
  échec, le jeton porte sur une autre donnée que ce manifeste.
- Les entrées à part (fichier d'en-têtes Bitcoin, second manifeste, pièces
  fournies à part) sont déclaratives comme le dossier, même quand c'est vous
  qui les fournissez (3.2, 4.1) : le vérificateur les contrôle par calcul.
  Une entrée lisible, conforme à son schéma quand elle en a un, qui contredit
  le calcul fait échouer sa vérification (O-5, P-5, E-6, EX-4.12) et rend le
  verdict « invalide ». Le verdict porte donc sur le dossier et sur les
  entrées à part fournies. La vérification en échec dit quelle entrée est en
  cause, et une nouvelle exécution du vérificateur sans cette entrée dit si
  le dossier seul est en défaut. De même, une contradiction avec votre
  fichier d'ancres (N-3, N-4, O-5, R-2, R-4, R-8, T-7, T-10) peut venir d'une
  erreur dans vos ancres. Ainsi, pour un jeton d'une autorité que votre
  fichier ne contient pas, le verdict dépend de vos ancres. Si votre fichier
  contient d'autres autorités, T-7 échoue et le dossier est « invalide »,
  pourvu que le certificat de l'unité soit connu (T-4 ; sinon, voir 7.3). Si
  vous n'avez pas de fichier d'ancres, ou s'il ne contient aucune autorité,
  le contrôle 4 est non exécuté (`ancre_absente`) et le verdict peut être
  « valide » borné (EX-4.9). Dans les deux cas, le dossier n'établit aucun
  horodatage par une autorité que vous acceptez. « Invalide » est le nom
  d'un verdict sur ce dossier, avec ces entrées et ces ancres : il ne dit
  pas que l'événement ou le jeton sont faux.

### 7.5 Verdict « incomplet » (code 3)

- Aucune vérification n'a échoué.
- Un contrôle que vous avez exigé avec `--exiger` n'a pas réussi.
- L'énoncé reste exact ; il prouve moins que ce que vous exigiez.
- `--exiger 5` est satisfait par un contrôle 5 réussi sur le réseau que
  déclare votre fichier d'ancres, `regtest` compris : ne déclarez `regtest`
  que pour des essais.

### 7.6 Code 2, entrée inutilisable

- Le vérificateur n'a pas vérifié le dossier. Il n'affirme rien, ni pour ni
  contre.
- La cause est nommée : usage, dossier illisible, schémas illisibles, fichier
  d'ancres inutilisable, entrée illisible, taille dépassée, erreur interne.
- Un fichier d'ancres défectueux donne le code 2, jamais un verdict : les
  ancres qu'il contient sont crues, non vérifiées (3.1), et son défaut ne
  dit rien du dossier. Ses certificats intermédiaires et ses listes de
  révocation ne sont pas crus pour autant : ils sont vérifiés comme ceux du
  jeton (T-7, T-10). Seule une liste complète qui porte le certificat de
  l'autorité à laquelle mène le chemin du jeton est prise telle quelle, sans
  vérification de sa signature, parce qu'elle ne peut que retirer la
  confiance (EX-9.16, 12.1). Une entrée à part illisible ou non conforme à
  son schéma donne aussi le code 2 (EX-4.12). Conforme, elle est
  déclarative et vérifiée comme le dossier : si elle contredit le calcul, le
  verdict est « invalide » (7.4).

### 7.7 Contrôle par contrôle

| Contrôle | Quand il réussit, il prouve | Il ne prouve pas | Qui ne peut plus tricher sur ce point |
|---|---|---|---|
| 1 | L'événement a la forme de CT-1 et l'empreinte qu'il annonce. | Que son contenu est vrai. | Quiconque modifie l'événement : la modification change son empreinte. |
| 2 | L'événement suit le voisin précédent et précède le suivant (ceux qui sont fournis), par leurs empreintes recalculées ; un voisin de la période adjacente, possible quand l'événement est le premier ou le dernier de la sienne, porte un `ts` déclaré hors d'elle (P-3 ; ce `ts` vient de l'horloge de l'enregistreur et n'est pas prouvé). | Que la chaîne est intacte au-delà des voisins fournis ; la racine du contrôle 3 couvre le reste de la période ; que les deux voisins appartiennent à la même période. | Quiconque insère, retire ou permute un événement entre ces voisins. |
| 3 | L'événement est la feuille d'indice `seq − first_seq` de l'arbre dont la racine est dans le manifeste ; le manifeste est signé par la clé déclarée. | Que le manifeste a été produit à l'heure qu'il annonce (`generated_at`) ; que l'événement a eu lieu entre `period_start` et `period_end`, bornes déclarées par le manifeste. | Quiconque présente l'événement dans une autre période ou à une autre place. |
| 4 | Le manifeste existait au plus tard à l'instant du jeton augmenté de sa précision, selon une autorité de votre fichier d'ancres. | Que l'autorité est qualifiée (c'est votre déclaration) ; que son heure est juste si elle ment ; que le certificat de l'autorité elle-même était dans ses dates (sauf unité épinglée, dont les dates sont contrôlées comme celles du certificat qui a signé le jeton) et non révoqué, sauf révocation portée par une CRL de votre fichier d'ancres ; une date chiffrée, si le jeton ne porte pas de précision ; la non-révocation d'un certificat du chemin au-delà de ce que dit la liste ou la déclaration retenue, dont la date n'a pas de limite haute (7.2). | L'opérateur, un enregistreur compromis après l'instant du jeton, le fournisseur NOORTRACE : une période réécrite ne passe plus avec ce jeton, et un nouveau jeton porterait un instant plus tardif. |
| 5 | Le manifeste existait avant la création d'un bloc Bitcoin relié à votre point de contrôle par la chaîne d'en-têtes fournie, sous k confirmations (bloc attesté compris : k − 1 blocs au-dessus de lui). Le travail n'est recalculé qu'au-dessus du point de contrôle, et peut ne l'être pour aucun bloc (7.2). | L'heure précise du bloc ; quoi que ce soit sur un réseau d'essai. | Les mêmes, et une autorité d'horodatage menteuse : la limite Bitcoin ne dépend pas d'elle. Pas un adversaire capable de miner autant de blocs que la chaîne fournie au-dessus du point de contrôle, à la difficulté du réseau. |
| 6 | La clé nommée a signé l'événement, ses voisins et le manifeste. Le `ts` de chaque événement et le `generated_at` du manifeste, tels que déclarés, tombent dans la période de validité que `cles.json` annonce pour la clé qui les signe (E-11, P-5), ce qui ne date pas la signature. | Que la clé appartient à l'organisation, sauf confirmation par le fichier d'ancres ou le registre, dans les limites dites en 7.2 ; que la validité annoncée est vraie ; l'instant de la signature : la période de validité est comparée aux instants déclarés, non au moment où la clé a signé. | Quiconque ne détient pas la clé privée de l'enregistreur et n'a pas l'usage de son signataire. L'opérateur peut en disposer (classes de garde C et D), ou s'en servir par le signataire de son enregistreur (classes A et B) (3.4). Le rapport ne dit pas la classe (7.2). |
| 7 | Les adresses nommées ont signé la décision que l'énoncé nomme (approbation ou refus), en nombre au moins égal au seuil déclaré ; une demande expirée ne porte aucune signature. | Qu'elles étaient habilitées ; que le jeu et le seuil déclarés sont ceux de l'organisation. | Quiconque ne détient pas les clés de ces adresses. |
| 8 | Un quorum du jeu de validateurs de votre fichier d'ancres a signé les blocs où les contrats de votre fichier d'ancres ont émis la clôture et l'ancre de ce `periodHash`. | Une date ; un fait d'état du registre (appartenance au `CuratorSet`, non-révocation d'une clé) ; que le code des contrats est celui de ce dépôt : `PeriodRegistry` et `AttestationRegistry` désignent dans l'énoncé les adresses que votre fichier d'ancres donne pour les rôles `period_registry` et `attestation_registry` (H7). | Quiconque contrôle moins d'un quorum des validateurs de ce jeu, y compris le fournisseur NOORTRACE s'il est dans ce cas. |

### 7.8 Hypothèses

Ces phrases supposent ce qui suit (détail en section 3.5) et, pour le
contrôle 8, que ses règles de calcul, tirées du code de noorcore, sont celles
du registre (paragraphe après la liste) :

- que le vérificateur exécuté est conforme à cette spécification : binaire
  reconstruit et comparé octet pour octet (section 14, à partir de la
  phase 2), ou implémentation de référence relue (3.1). Relire celle-ci
  suppose aussi de croire l'environnement Node qui l'exécute, que cette
  spécification n'épingle pas. Le rapport en donne la version (ligne
  `Vérificateur`, champ `verifier.runtime`). Cela suppose encore de croire
  la bibliothèque `ethers` que l'implémentation de référence importe, avec
  ses dépendances. `package-lock.json` en fixe la version, que le rapport ne
  donne pas ;
- qu'on ne sait ni trouver de collision de SHA-256 ou de Keccak-256, ni
  forger une signature sans la clé privée (H1, H2) ;
- que votre fichier d'ancres dit vrai (H3), pour les ancres qu'il donne. Ses
  intermédiaires et ses listes de révocation sont vérifiés, non crus, sauf
  une liste complète qui porte le certificat de l'autorité à laquelle mène
  le chemin du jeton (EX-9.16, 12.1) ;
- que l'autorité d'horodatage n'a pas menti sur l'heure (H4), pour la limite
  « au plus tard » tirée du jeton (contrôle 4), que le contrôle 5 ait réussi
  ou non. Le bloc Bitcoin donne une autre limite, qui ne dépend pas d'elle,
  mais il ne confirme ni ne corrige l'heure du jeton ;
- que personne n'a pu miner les blocs fournis au-dessus de votre point de
  contrôle (H5), pour ce qui repose sur le contrôle 5 ;
- qu'au plus f = ⌊(N − 1)/3⌋ des N validateurs de votre jeu sont fautifs,
  c'est-à-dire strictement moins d'un tiers : 1 sur 4, 0 sur 3, 1 sur 6
  (H6), pour ce qui repose sur le contrôle 8 ;
- que le code des contrats aux adresses de votre fichier d'ancres est celui de
  ce dépôt (H7). Sans H7, le contrôle 8 établit encore que ces adresses ont
  émis les événements `PeriodSubmitted`, `Anchored` et, s'il y en a,
  `RecorderRegistered`, dans des blocs signés par un quorum de votre jeu
  (H6).
  H7 est ce qui leur donne le sens d'une clôture, d'une ancre ou d'une
  inscription de clé admise par le contrat (`recorder_registry`, provenance
  « inscrite au registre »).

Les règles qui donnent son sens au contrôle 8 viennent du code de noorcore,
dépôt privé, et d'expériences sur le réseau de développement (section 0,
annexe B.3) : préimage de `BFTBlockHash`, condensé signé par chaque
validateur, hachage du jeu, formule du quorum, champs qu'un validateur
contrôle avant de signer. Elles ne sont pas recoupables publiquement. Un
réviseur qui n'a pas accès à ce code les tient de NOORTRACE. La
confrontation de l'annexe A.8 compare la racine des reçus et le décodage des
journaux à go-ethereum, outil public. Elle compare en revanche le hachage de
bloc et les enveloppes à des fonctions de noorcore. Plus généralement, un
fait que l'annexe B dit « non recoupable » repose sur la note, R1 à R4, qui
le rapporte.

La « borne sous hypothèse » du contrôle 5 repose sur sa propre hypothèse
(EX-10.13), hors de cette liste, parce qu'elle n'est pas prouvée (7.1) et
qu'aucune phrase de 7.2 n'en dépend.

## 8. Interface

### 8.1 Commande

```text
noortrace-verifier <répertoire> [--ancres <fichier>] [--entetes-bitcoin <fichier>]
                   [--pieces <répertoire>] [--second-manifeste <fichier>]
                   [--exiger <contrôles>] [--langue fr|en] [--json] [--detail]
noortrace-verifier --version
noortrace-verifier --aide

node scripts/verify/dossier.mjs <répertoire> [mêmes options] [--schemas <répertoire>]
npm run verify:dossier -- <répertoire> [mêmes options]
```

**EX-8.1** Le binaire s'appelle `noortrace-verifier`. L'implémentation de
référence est `scripts/verify/dossier.mjs`. Les deux acceptent les mêmes
options et rendent les mêmes codes de retour. Seule l'implémentation de
référence accepte `--schemas` ; le binaire embarque les schémas de sa version
et n'en lit aucun sur le disque.

### 8.2 Options

| Option | Valeur | Effet | Défaut |
|---|---|---|---|
| `<répertoire>` | chemin | le dossier ; exactement un | obligatoire |
| `--ancres` | fichier | fichier d'ancres du réviseur (section 4.4) | aucun |
| `--entetes-bitcoin` | fichier | chaîne d'en-têtes Bitcoin (EX-4.5) | aucune |
| `--pieces` | répertoire | pièces nommées par leur `sha256` (EX-4.6) | aucune |
| `--second-manifeste` | fichier | manifeste précédent ou suivant du même journal (EX-4.7) | aucun |
| `--exiger` | numéros de contrôles de 1 à 8 séparés par `,`, ou `tous` | un contrôle exigé qui n'a pas réussi rend le verdict `incomplet` (code 3) ; `tous` inclut le contrôle 7, non exécuté pour un événement sans approbation | aucun |
| `--langue` | `fr` ou `en` | langue de la sortie lisible et des textes du rapport JSON | `fr` |
| `--json` | — | rapport JSON sur la sortie standard, au lieu du rapport lisible | rapport lisible |
| `--detail` | — | rapport lisible : toutes les vérifications, pas seulement celles qui n'ont pas réussi | non |
| `--schemas` | répertoire | implémentation de référence seulement : répertoire des schémas | `spec/schemas` |
| `--version` | — | imprime le nom, la version, l'environnement d'exécution et le SHA-256 de chaque schéma embarqué, puis sort | — |
| `--aide`, `--help` | — | imprime l'aide, puis sort | — |

**EX-8.2** Une option inconnue, une option répétée, une option sans sa
valeur, une valeur hors de son domaine, zéro ou plusieurs répertoires rendent
le code 2, type d'erreur `usage`. `--option=valeur` et `--option valeur` sont
équivalents. `--version` et `--aide` (ou `--help`) sont exclusives : elles ne
se combinent qu'avec `--langue` (et, pour l'implémentation de référence,
`--schemas`) ; avec un répertoire, avec toute autre option ou l'une avec
l'autre, elles rendent le code 2, type `usage` (avec `--json`, ce rapport
d'erreur est en JSON, EX-8.5). Seules, elles impriment leur texte sur la
sortie standard et sortent avec le code 0.

**EX-8.3** `--langue` change les textes, jamais les identifiants, les statuts,
les raisons, le verdict ni le code de retour. Le rapport JSON porte l'énoncé
dans les deux langues, quelle que soit `--langue` ; ses autres textes
(`summary`, `detail`, `bound`, `error.message`) sont dans la langue choisie.
Aucune variable d'environnement (`LANG`, `LC_ALL`, fuseau horaire) ne change
la sortie.

### 8.3 Codes de retour

| Code | Verdict | Sens | Affirmation sur le dossier |
|---|---|---|---|
| 0 | `valide` | Aucune vérification en échec ; toute non-exécution a une raison admise ; tout contrôle exigé par `--exiger` a réussi. | Oui : l'énoncé. |
| 1 | `invalide` | Au moins une vérification en échec, ou non exécutée sans raison admise. | Oui : ce dossier ne prouve pas l'événement. |
| 2 | aucun | Entrée inutilisable : usage incorrect, dossier, schémas, fichier d'ancres ou entrée à part illisibles, limite de taille dépassée, erreur interne du vérificateur. | Aucune. |
| 3 | `incomplet` | Comme 0, mais un contrôle exigé par `--exiger` n'a pas réussi. | Oui : l'énoncé, qui prouve moins que l'exigence. |

**EX-8.4** Le vérificateur rend les codes de cette table, et seulement eux.
Les codes 0, 1 et 2 gardent le sens qu'ils ont dans la version CT-1 de
`scripts/verify/dossier.mjs`. Le code 3 n'apparaît qu'avec `--exiger` : un
réviseur qui a besoin d'une date prouvée obtient un code non nul sans
confondre « incomplet » et « faux », ce que `ots verify` confond (code 1 dans
les deux cas, R4 F6.05). Une erreur interne rend le code 2, type
`erreur_interne`, et non un verdict : dans les deux cas rien n'est affirmé, et
le type d'erreur les distingue.

**EX-8.5** Le vérificateur écrit le rapport, lisible ou JSON, sur la sortie
standard, et rien d'autre ; il écrit les messages d'erreur et les
avertissements sur la sortie d'erreur. Avec `--json`, la sortie standard est
toujours un document JSON conforme au schéma `rapport-verification-v0`, y
compris pour le code 2.

### 8.4 Langue

Les deux langues ont les mêmes lignes, dans le même ordre. Libellés des
statuts : `[réussi]`, `[ÉCHEC]`, `[non exécuté]` en français ; `[passed]`,
`[FAILED]`, `[not run]` en anglais. Libellés des huit contrôles :

| N° | Français | Anglais |
|---|---|---|
| 1 | hachage canonique de l'événement | canonical hash of the event |
| 2 | chaînage avec les voisins | chaining with the neighbours |
| 3 | inclusion dans la racine du manifeste | inclusion in the manifest root |
| 4 | jeton d'horodatage RFC 3161 sur periodHash | RFC 3161 time-stamp token on periodHash |
| 5 | preuve OpenTimestamps et en-têtes Bitcoin | OpenTimestamps proof and Bitcoin headers |
| 6 | signatures de l'enregistreur | recorder signatures |
| 7 | signatures des approbateurs et seuil | approver signatures and threshold |
| 8 | inclusion au registre, bloc certifié par un quorum | registry inclusion, quorum-certified block |

Les libellés des vérifications T-, O-, R- et N- sont ceux des tables 9.5,
10.4, 11.4 et 12.4, en français ou en anglais. Ceux des vérifications de CT-1
résument les règles de sa table 11.4, qui n'a pas de version anglaise :
l'implémentation les traduit. V-5 ne compare que l'énoncé et la borne, pas les
libellés.

### 8.5 Sortie lisible

**EX-8.6** Le rapport lisible comporte ces lignes, dans cet ordre ; les
étiquettes des lignes à valeur unique (`Vérificateur`, `Répertoire`, `Index`,
`Ancres`, `Événement`, `Borne`, `Résultat`, `Énoncé`…) sont complétées par
des espaces jusqu'à quatorze caractères avant les deux-points, comme dans
CT-1 :

1. le titre ;
2. `Vérificateur` : nom, version, environnement d'exécution ;
3. `Répertoire` ; `Index` : SHA-256 de `dossier.json` ;
4. `Ancres` : chemin et SHA-256, ou `aucun fichier d'ancres` ; puis, si elles
   sont fournies, `En-têtes`, `Pièces` et `2e manifeste` ;
5. `Événement`, `Journal` et `Période`, quand les parties qui les portent sont
   exploitables ;
6. `Contrôles de l'architecture :` puis une ligne par contrôle :
   `  [statut] N  libellé — résumé`, et pour un contrôle non exécuté
   `— non exécuté (raison) : résumé` ;
7. `Vérifications non réussies :` (toutes les vérifications avec `--detail`,
   sous le titre `Vérifications :`) puis, pour chacune, `  [statut] id
   [contrôles] libellé` et, en dessous, son détail suivi de la raison entre
   parenthèses ;
8. `Avertissements :` puis, pour chaque avertissement des sections 9 à 11,
   `  AV-… (vérification) détail` ;
9. `Parties absentes :` si l'index en déclare ;
10. `Borne` si la borne n'est pas nulle ;
11. `Résultat` : `VALIDE — aucune vérification en échec, aucune vérification
    non exécutée sans raison admise`, `INVALIDE — vérification(s) en échec :
    {ids}` suivi de ` ; vérification(s) non exécutée(s) sans raison admise :
    {ids}` s'il y en a, ou `INCOMPLET — contrôle(s) exigé(s) non réussi(s) :
    {numéros}` ;
12. `Énoncé` : l'énoncé dans la langue de sortie, sauf pour le code 2.

Pour le code 2, le rapport lisible se réduit à la ligne `Erreur : {message}`
sur la sortie d'erreur, comme dans CT-1.

Dossier `valide-seq-7-complet` des vecteurs de CT-6 (annexe A, EX-A.11),
vérifié avec `ancres-test.json` et `chaine.json` par l'implémentation de
référence. Les valeurs sont celles des vecteurs publiés ; l'énoncé est égal à
celui de l'`attendu.json` du dossier (V-5). Dans cet exemple et les suivants,
les chemins absolus que le vérificateur imprime sont abrégés en `…/` (racine
du dépôt), et la version de Node est celle de la machine qui a produit
l'exemple. Le contrôle 4 réussit alors que T-11 n'est
pas exécutée : l'ancre de test ne déclare aucun statut qualifié, et T-11 est
sans effet sur le statut (EX-9.18). Les heures déclarées par les blocs du
registre (octobre 2026) précèdent les dates fictives du manifeste (novembre
2026) : c'est une particularité des vecteurs (EX-A.9), sans effet sur le
verdict. Cet exemple n'emploie que des données de test : une autorité
d'horodatage de test, le réseau Bitcoin `regtest` (contrôle 5 sans valeur
probante, AV-O-3), et le registre et le jeu de validateurs du réseau de
développement, déclarés par une ancre de test. Il montre la forme d'un
rapport aux huit contrôles réussis, pas un verdict probant. Ce que vaut le
contrôle 8 dépend du jeu de validateurs que le réviseur déclare (H3, H6).

```text
$ node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet --ancres spec/vecteurs/ct-6/ancres/ancres-test.json --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json
Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)
Vérificateur  : scripts/verify/dossier.mjs 0.1.0 (node v22.22.0)
Répertoire    : …/spec/vecteurs/ct-6/dossiers/valide-seq-7-complet
Index         : dossier.json, SHA-256 0x314e835f7f808e4dfe79be546284d666022093f14c7d19633bf7dfecd0d9b7f7
Ancres        : …/spec/vecteurs/ct-6/ancres/ancres-test.json, SHA-256 0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617
En-têtes      : …/spec/vecteurs/ct-6/ots/entetes/chaine.json, SHA-256 0x4c2b5496dc33b2395ee6e768595f23b56d06f9e725e7a56b789b19985430b9ba
Événement     : seq 7, hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14, ts 2026-11-05T09:31:48.006Z, outil sap.payments.create
Journal       : org_id 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal_id 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164
Période       : 2026-11-05T09:00:00Z à 2026-11-05T10:00:00Z, periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
Contrôles de l'architecture :
  [réussi]      1  hachage canonique de l'événement — hachage canonique recalculé égal à hash
  [réussi]      2  chaînage avec les voisins — chaîné aux voisins seq 6 et 8
  [réussi]      3  inclusion dans la racine du manifeste — feuille 6 de l'arbre de 9 du manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
  [réussi]      4  jeton d'horodatage RFC 3161 sur periodHash — selon AC de test CT-6 (unité TSA de test CT-6), au plus tard 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré
  [réussi]      5  preuve OpenTimestamps et en-têtes Bitcoin — bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)
  [réussi]      6  signatures de l'enregistreur — rec-test-01 (événement), rec-test-02 (manifeste), clés fournies par le fichier d'ancres
  [réussi]      7  signatures des approbateurs et seuil — apr-2201 : 2 signatures, seuil 2 sur 3 ; A-4 hors dossier
  [réussi]      8  inclusion au registre, bloc certifié par un quorum — noortrace-2124-dev : inscriptions blocs 16648 et 16652, ancre bloc 16660, clôture bloc 16668, 3 validateurs sur 4 à chaque bloc
Vérifications non réussies :
  [non exécuté] A-4  [7] request_hash = hash recalculé de l'événement de demande (status retenue) quand il est dans le dossier
                      événement de demande (request_hash 0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d) absent du dossier : non vérifiable (piece_hors_dossier)
  [non exécuté] T-11 [4] statut qualifié déclaré par l'ancre
                      l'ancre /tsa_authorities/0 ne déclare aucun statut qualifié (ancre_absente)
Avertissements :
  AV-O-3 (O-5) réseau regtest : réseau d'essai, sans valeur probante hors des tests
Résultat      : VALIDE — aucune vérification en échec, aucune vérification non exécutée sans raison admise
Énoncé        : L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait au plus tard le 2026-11-05T10:00:06Z UTC ; le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait avant la création du bloc Bitcoin 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante) ; sur le registre noortrace-2124-dev, la clôture de cette période (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) figure au bloc 16668 (heure déclarée par le bloc : 2026-10-22T22:20:56Z UTC), émise par le contrat PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, et son ancre 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 au bloc 16660 (heure déclarée 2026-10-22T22:20:49Z UTC), émise par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 pour l'émetteur 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, clé de chaîne inscrite au bloc 16652 pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 que le réviseur déclare (validators.json du réseau de développement, clés publiques seulement).
$ echo $?
0
```

Le même dossier, en anglais :

```text
$ node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet --ancres spec/vecteurs/ct-6/ancres/ancres-test.json --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json --langue en
Offline verification of a NOORTRACE evidence dossier (format v0, CT-1 and CT-6)
Verifier      : scripts/verify/dossier.mjs 0.1.0 (node v22.22.0)
Directory     : …/spec/vecteurs/ct-6/dossiers/valide-seq-7-complet
Index         : dossier.json, SHA-256 0x314e835f7f808e4dfe79be546284d666022093f14c7d19633bf7dfecd0d9b7f7
Anchors       : …/spec/vecteurs/ct-6/ancres/ancres-test.json, SHA-256 0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617
Headers       : …/spec/vecteurs/ct-6/ots/entetes/chaine.json, SHA-256 0x4c2b5496dc33b2395ee6e768595f23b56d06f9e725e7a56b789b19985430b9ba
Event         : seq 7, hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14, ts 2026-11-05T09:31:48.006Z, tool sap.payments.create
Journal       : org_id 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal_id 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164
Period        : 2026-11-05T09:00:00Z to 2026-11-05T10:00:00Z, periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
Architecture controls:
  [passed]      1  canonical hash of the event — recomputed canonical hash equals hash
  [passed]      2  chaining with the neighbours — chained to neighbours seq 6 and 8
  [passed]      3  inclusion in the manifest root — leaf 6 of the 9-leaf tree of manifest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
  [passed]      4  RFC 3161 time-stamp token on periodHash — according to AC de test CT-6 (unit TSA de test CT-6), no later than 2026-11-05T10:00:06Z; no qualified status declared
  [passed]      5  OpenTimestamps proof and Bitcoin headers — Bitcoin block 1001 on network regtest, 20 confirmations (test network)
  [passed]      6  recorder signatures — rec-test-01 (event), rec-test-02 (manifest), keys given by the anchors file
  [passed]      7  approver signatures and threshold — apr-2201: 2 signatures, threshold 2 of 3; A-4 outside the dossier
  [passed]      8  registry inclusion, quorum-certified block — noortrace-2124-dev: registrations blocks 16648 and 16652, anchor block 16660, closing block 16668, 3 of 4 validators in each block
Checks not passed:
  [not run]     A-4  [7] request_hash = recomputed hash of the request event (status retenue) when it is in the dossier
                      request event (request_hash 0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d) not in the dossier: cannot be checked (piece_hors_dossier)
  [not run]     T-11 [4] qualified status declared by the anchor
                      the anchor /tsa_authorities/0 declares no qualified status (ancre_absente)
Warnings:
  AV-O-3 (O-5) regtest network: a test network, no evidential value outside tests
Result        : VALID — no failed check, no check left unrun without an admitted reason
Statement     : Event seq 7 (hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) of journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 of organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab is well-formed, chained to its neighbours seq 6 and 8 and included in the period from 2026-11-05T09:00:00Z to 2026-11-05T10:00:00Z closed by manifest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914; the event is signed by recorder key rec-test-01 and the manifest by key rec-test-02, keys given by the anchors file; the event was approved by 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 and 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, threshold 2 of 3 of the set declared by the dossier); according to AC de test CT-6 (unit TSA de test CT-6), the manifest with digest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existed no later than 2026-11-05T10:00:06Z UTC; the manifest with digest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existed before Bitcoin block 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, regtest network) was created, under 20 blocks whose work connects to the reviewer's checkpoint 1000; time written by the miner: 2026-11-05T13:50:00Z UTC, accuracy not guaranteed by the protocol; bound under assumption: 2026-11-05T14:50:00Z UTC (test network, no evidential value); on registry noortrace-2124-dev, the closing of this period (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) is in block 16668 (time declared by the block: 2026-10-22T22:20:56Z UTC), emitted by contract PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, and its anchor 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 in block 16660 (declared time 2026-10-22T22:20:49Z UTC), emitted by AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 for issuer 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, chain key registered in block 16652 for recorder key rec-test-02, which the reviewer holds as the chain key of rec-test-02; each of these blocks is signed by 3 of the 4 validators of set 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 declared by the reviewer (validators.json du réseau de développement, clés publiques seulement).
$ echo $?
0
```

Dossier CT-1 `valide-seq-7` tel que publié, sans fichier d'ancres : verdict
borné, code 0, comme avant CT-6 (EX-6.14) :

```text
$ node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7
Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)
Vérificateur  : scripts/verify/dossier.mjs 0.1.0 (node v22.22.0)
Répertoire    : …/spec/vecteurs/ct-1/dossiers/valide-seq-7
Index         : dossier.json, SHA-256 0x618063a0dc01a7397bd0a21f62b99b29476cf38950e3705e9d09a63ac68f07f0
Ancres        : aucun fichier d'ancres
Événement     : seq 7, hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14, ts 2026-11-05T09:31:48.006Z, outil sap.payments.create
Journal       : org_id 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal_id 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164
Période       : 2026-11-05T09:00:00Z à 2026-11-05T10:00:00Z, periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
Contrôles de l'architecture :
  [réussi]      1  hachage canonique de l'événement — hachage canonique recalculé égal à hash
  [réussi]      2  chaînage avec les voisins — chaîné aux voisins seq 6 et 8
  [réussi]      3  inclusion dans la racine du manifeste — feuille 6 de l'arbre de 9 du manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
  [non exécuté] 4  jeton d'horodatage RFC 3161 sur periodHash — non exécuté (hors_perimetre_version) : jeton-rfc3161.der absent (hors périmètre CT-1)
  [non exécuté] 5  preuve OpenTimestamps et en-têtes Bitcoin — non exécuté (hors_perimetre_version) : preuve.ots absent (hors périmètre CT-1)
  [réussi]      6  signatures de l'enregistreur — rec-test-01 (événement), rec-test-02 (manifeste), clés déclarées par le dossier
  [réussi]      7  signatures des approbateurs et seuil — apr-2201 : 2 signatures, seuil 2 sur 3 ; A-4 hors dossier
  [non exécuté] 8  inclusion au registre, bloc certifié par un quorum — non exécuté (hors_perimetre_version) : registre.json, certificat-commit.json, validateurs.json absents (hors périmètre CT-1)
Vérifications non réussies :
  [non exécuté] A-4  [7] request_hash = hash recalculé de l'événement de demande (status retenue) quand il est dans le dossier
                      événement de demande (request_hash 0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d) absent du dossier : non vérifiable (piece_hors_dossier)
Parties absentes : jeton-rfc3161.der (hors périmètre CT-1), preuve.ots (hors périmètre CT-1), registre.json (hors périmètre CT-1), certificat-commit.json (hors périmètre CT-1), validateurs.json (hors périmètre CT-1)
Borne         : verdict borné : contrôle 4 non exécuté (hors_perimetre_version), contrôle 5 non exécuté (hors_perimetre_version), contrôle 8 non exécuté (hors_perimetre_version)
Résultat      : VALIDE — aucune vérification en échec, aucune vérification non exécutée sans raison admise
Énoncé        : L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés déclarées par le dossier ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; ce dossier ne prouve rien sur sa date (contrôles 4 et 5) ni sur son inscription au registre (contrôle 8).
$ echo $?
0
```

Le même dossier avec `--exiger 4,5,8` rend le code 3 ; seule la ligne
`Résultat` change :

```text
Résultat      : INCOMPLET — contrôle(s) exigé(s) non réussi(s) : 4, 5, 8
```

Dossier CT-1 `invalide-hash-faux` (le champ `hash` de `evenement.json`
réécrit, contenu et signature intacts, l'index recalculé pour que D-1 et D-2
passent) : code 1. La ligne `Événement` reprend
le `hash` écrit dans le fichier (`0xdae5…7705`), qui est faux : c'est ce que
E-7 signale.

```text
$ node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux
Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)
Vérificateur  : scripts/verify/dossier.mjs 0.1.0 (node v22.22.0)
Répertoire    : …/spec/vecteurs/ct-1/dossiers/invalide-hash-faux
Index         : dossier.json, SHA-256 0xa0168e7b7f318b299e17e978bc14f2f513c17b3b51870c5c6bf8bdc7aaea5c39
Ancres        : aucun fichier d'ancres
Événement     : seq 7, hash 0xdae5709042b9fd82eefadfaa9f2e6095a20d9b0f77b249a082cd286d424b7705, ts 2026-11-05T09:31:48.006Z, outil sap.payments.create
Journal       : org_id 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal_id 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164
Période       : 2026-11-05T09:00:00Z à 2026-11-05T10:00:00Z, periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
Contrôles de l'architecture :
  [ÉCHEC]       1  hachage canonique de l'événement — vérification(s) en échec : E-7
  [réussi]      2  chaînage avec les voisins — chaîné aux voisins seq 6 et 8
  [réussi]      3  inclusion dans la racine du manifeste — feuille 6 de l'arbre de 9 du manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914
  [non exécuté] 4  jeton d'horodatage RFC 3161 sur periodHash — non exécuté (hors_perimetre_version) : jeton-rfc3161.der absent (hors périmètre CT-1)
  [non exécuté] 5  preuve OpenTimestamps et en-têtes Bitcoin — non exécuté (hors_perimetre_version) : preuve.ots absent (hors périmètre CT-1)
  [réussi]      6  signatures de l'enregistreur — rec-test-01 (événement), rec-test-02 (manifeste), clés déclarées par le dossier
  [réussi]      7  signatures des approbateurs et seuil — apr-2201 : 2 signatures, seuil 2 sur 3 ; A-4 hors dossier
  [non exécuté] 8  inclusion au registre, bloc certifié par un quorum — non exécuté (hors_perimetre_version) : registre.json, certificat-commit.json, validateurs.json absents (hors périmètre CT-1)
Vérifications non réussies :
  [ÉCHEC]       E-7  [1] hash recalculé depuis l'objet égal à hash
                      evenement : hash recalculé 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14 différent de hash 0xdae5709042b9fd82eefadfaa9f2e6095a20d9b0f77b249a082cd286d424b7705 ; voisin précédent : hash 0x097ae3f842959999b67d2ceb971d94c58279b42b04a5fca1bd47d09914080009 ; voisin suivant : hash 0x74f7dd908e35792023f6238ff1bc8999a0a24a7b025d65d58a810ac5701f9eb5 ; approbation[0] : hash 0x097ae3f842959999b67d2ceb971d94c58279b42b04a5fca1bd47d09914080009
  [non exécuté] A-4  [7] request_hash = hash recalculé de l'événement de demande (status retenue) quand il est dans le dossier
                      événement de demande (request_hash 0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d) absent du dossier : non vérifiable (piece_hors_dossier)
Parties absentes : jeton-rfc3161.der (hors périmètre CT-1), preuve.ots (hors périmètre CT-1), registre.json (hors périmètre CT-1), certificat-commit.json (hors périmètre CT-1), validateurs.json (hors périmètre CT-1)
Borne         : verdict borné : contrôle 4 non exécuté (hors_perimetre_version), contrôle 5 non exécuté (hors_perimetre_version), contrôle 8 non exécuté (hors_perimetre_version)
Résultat      : INVALIDE — vérification(s) en échec : E-7
Énoncé        : Dossier invalide : vérification(s) en échec : E-7 ; le vérificateur n'affirme rien sur cet événement.
$ echo $?
1
```

### 8.6 Sortie JSON

**EX-8.7** Avec `--json`, le vérificateur écrit un document conforme à
`spec/schemas/rapport-verification-v0.schema.json` (JSON Schema 2020-12,
`$id` `https://noortrace.example/schemas/v0/rapport-verification.schema.json`) :
un rapport (codes 0, 1, 3) ou un rapport d'erreur (code 2). Deux exécutions
sur les mêmes entrées, avec la même implémentation à la même version,
écrivent le même document octet pour octet, aux chemins de `inputs` près ; la
mise en forme (indentation, ordre des clés) suit l'ordre du schéma.

| Clé | Contenu |
|---|---|
| `format`, `version` | `noortrace/rapport-verification`, `0`. |
| `verifier` | `name`, `implementation` (`binaire_go` ou `reference_javascript`), `version`, `runtime` (version de Go ou de Node) et `schemas` : identifiant et SHA-256 de chacun des huit schémas que la version embarque, quelles que soient les options, dans cet ordre : `evenement`, `manifeste`, `dossier`, `registre`, `validateurs`, `ancres-confiance`, `entetes-bitcoin`, `rapport-verification`. La version de Go est rapportée parce que le comportement de la bibliothèque standard varie entre versions : lecture des certificats et vérification des signatures par `crypto/x509`, et `encoding/asn1` (avis GO-2025-4011 et GO-2026-5972, R4 F3.14) ; GO-2026-6809, qui change le résultat de `Certificate.Verify`, ne touche pas T-7, dont la validation de chemin est faite par le code du vérificateur (EX-14.4). |
| `language` | `fr` ou `en`. |
| `inputs` | Chemin et SHA-256 de chaque entrée lue (`dossier.index_sha256` : SHA-256 de `dossier.json`), `null` pour une entrée non fournie ; `required_controls` : les contrôles de `--exiger`. |
| `event`, `org_id`, `journal_id`, `period` | Désignation de l'événement et de sa période (EX-6.13) ; `period.period_hash` est le `periodHash` recalculé. |
| `controls` | Les huit contrôles, dans l'ordre : `number`, `status`, `reason` (`null` sauf `non_execute`), `checks` (vérifications rattachées présentes dans le rapport), `anchors_used` (pointeurs JSON, RFC 6901, vers les ancres employées dans le fichier d'ancres : `/tsa_authorities/0`, `/bitcoin`, `/registry/validator_sets/0`, `/recorders/1`…), `summary` (résumé dans la langue choisie). |
| `checks` | Les vérifications dans l'ordre de la section 5.2 : `id`, `controls` (contrôles servis, vide pour D-1 et D-2), `status`, `reason` et `admitted` (`null` sauf `non_execute`), `detail`. |
| `failed_checks`, `blocking_unexecuted` | EX-6.7. |
| `absent_parts` | Les parties déclarées absentes dans l'index, avec leur raison, comme dans CT-1. |
| `warnings` | Les avertissements des sections 9 à 11 (`id` AV-…, `check`, `detail`), dans l'ordre de EX-6.15 ; un avertissement ne change aucun statut. |
| `facts` | Les valeurs établies par les contrôles réussis (EX-6.13) : clés d'enregistreur et leur provenance (`source` : `dossier`, `ancres`, `registre`, ou `mixte` quand les deux clés diffèrent de provenance ; `event_key_source` et `manifest_key_source`, provenance de chaque clé, EX-6.8), approbation (`decision`, `ticket`, `approvers`, vide pour `expire`, `required`, `size`, `set_source`), et, pour les contrôles 4, 5 et 8, les valeurs que EX-9.19, EX-10.14 et EX-11.21 exigent ; dans un rapport `invalide`, aide au diagnostic seulement (EX-6.13). |
| `verdict`, `exit_code` | Section 8.3 ; le schéma impose leur concordance. |
| `statement` | L'énoncé, `fr` et `en`, quelle que soit `--langue`. |
| `bound` | La borne (EX-6.12) ou `null`. |
| `error` | Rapport d'erreur seulement : `kind` (`usage`, `dossier_illisible`, `schemas_illisibles`, `ancres_inutilisables`, `entree_illisible`, `taille_depassee`, `erreur_interne`), `message`, `check` (la vérification N- en cause, ou `null`). |

Rapport JSON du dossier complet de la section 8.5, avec les mêmes valeurs
que le rapport lisible (chemins abrégés de même) ; le document est valide
contre le schéma (`npx --yes ajv-cli@5
validate --spec=draft2020 --strict=true`) :

<!-- schema: rapport-verification -->
```json
{
  "format": "noortrace/rapport-verification",
  "version": 0,
  "verifier": {
    "name": "scripts/verify/dossier.mjs",
    "implementation": "reference_javascript",
    "version": "0.1.0",
    "runtime": "node v22.22.0",
    "schemas": [
      { "id": "https://noortrace.example/schemas/v0/evenement.schema.json", "sha256": "0xcd2efffae72ebe2d00459ac643785415ad25d138325681aca6127a0a2fa0393f" },
      { "id": "https://noortrace.example/schemas/v0/manifeste.schema.json", "sha256": "0x1341dd18b1cc4b570c13ed4010228b13b78d1582292ea7ecba0ce1ac7a462bf2" },
      { "id": "https://noortrace.example/schemas/v0/dossier.schema.json", "sha256": "0xeca29ac0c6329e4434529dd07d82e2a93fd897fe875e7812b04f5734d9dc8fe5" },
      { "id": "https://noortrace.example/schemas/v0/registre.schema.json", "sha256": "0xcd9fff826267865fe43d37bb4a42bb3f0ba0d04d56be0fff67d306e5960131c8" },
      { "id": "https://noortrace.example/schemas/v0/validateurs.schema.json", "sha256": "0x233e7ee41d597119c9319382eacc673f316fe891f8e271cc1032a183972825fd" },
      { "id": "https://noortrace.example/schemas/v0/ancres-confiance.schema.json", "sha256": "0x1ab686a61d7dad8ea8e1d26b69e750e414b19e819f9a3516cb1d7c737c807d04" },
      { "id": "https://noortrace.example/schemas/v0/entetes-bitcoin.schema.json", "sha256": "0x77e991e484add0e308291578d8576c28a4264b5d2b2ae2c06b6832b470b6308c" },
      { "id": "https://noortrace.example/schemas/v0/rapport-verification.schema.json", "sha256": "0x4ade757ae8ecc1c9ae3bd6d32f33700349ffd0484862719f12ab808265109c55" }
    ]
  },
  "language": "fr",
  "inputs": {
    "dossier": {
      "path": "…/spec/vecteurs/ct-6/dossiers/valide-seq-7-complet",
      "index_sha256": "0x314e835f7f808e4dfe79be546284d666022093f14c7d19633bf7dfecd0d9b7f7"
    },
    "anchors": {
      "path": "…/spec/vecteurs/ct-6/ancres/ancres-test.json",
      "sha256": "0x2be4619fb82ce615244c78a054e71930322bc0bed894521dca5f8d6a3b6dc617"
    },
    "bitcoin_headers": {
      "path": "…/spec/vecteurs/ct-6/ots/entetes/chaine.json",
      "sha256": "0x4c2b5496dc33b2395ee6e768595f23b56d06f9e725e7a56b789b19985430b9ba"
    },
    "second_manifest": null,
    "pieces": null,
    "required_controls": []
  },
  "event": {
    "seq": 7,
    "hash": "0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14",
    "ts": "2026-11-05T09:31:48.006Z",
    "tool": "sap.payments.create"
  },
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "period": {
    "period_start": 1793869200,
    "period_end": 1793872800,
    "period_hash": "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914"
  },
  "controls": [
    { "number": 1, "status": "reussi", "reason": null, "checks": ["E-1", "E-2", "E-3", "E-4", "E-6", "E-7"], "anchors_used": [], "summary": "hachage canonique recalculé égal à hash" },
    { "number": 2, "status": "reussi", "reason": null, "checks": ["C-1", "C-2", "P-3"], "anchors_used": [], "summary": "chaîné aux voisins seq 6 et 8" },
    { "number": 3, "status": "reussi", "reason": null, "checks": ["M-1", "M-2", "M-3", "P-1", "P-2", "P-3", "P-4", "P-5"], "anchors_used": [], "summary": "feuille 6 de l'arbre de 9 du manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914" },
    { "number": 4, "status": "reussi", "reason": null, "checks": ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11"], "anchors_used": ["/tsa_authorities/0", "/revocation/crls/0"], "summary": "selon AC de test CT-6 (unité TSA de test CT-6), au plus tard 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré" },
    { "number": 5, "status": "reussi", "reason": null, "checks": ["O-1", "O-2", "O-3", "O-4", "O-5", "O-6", "O-7"], "anchors_used": ["/bitcoin"], "summary": "bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)" },
    { "number": 6, "status": "reussi", "reason": null, "checks": ["E-8", "E-10", "E-11", "C-3", "P-5", "N-3"], "anchors_used": ["/recorders/0", "/recorders/1"], "summary": "rec-test-01 (événement), rec-test-02 (manifeste), clés fournies par le fichier d'ancres" },
    { "number": 7, "status": "reussi", "reason": null, "checks": ["E-5", "E-9", "A-1", "A-2", "A-3", "A-4"], "anchors_used": [], "summary": "apr-2201 : 2 signatures, seuil 2 sur 3 ; A-4 hors dossier" },
    { "number": 8, "status": "reussi", "reason": null, "checks": ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-4"], "anchors_used": ["/registry", "/registry/validator_sets/0", "/recorders/1"], "summary": "noortrace-2124-dev : inscriptions blocs 16648 et 16652, ancre bloc 16660, clôture bloc 16668, 3 validateurs sur 4 à chaque bloc" }
  ],
  "checks": [
    { "id": "D-1", "controls": [], "status": "reussi", "reason": null, "admitted": null, "detail": "dossier.json conforme au schéma" },
    { "id": "D-2", "controls": [], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-1", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-2", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-3", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-4", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-5", "controls": [7], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-6", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-7", "controls": [1], "status": "reussi", "reason": null, "admitted": null, "detail": "evenement : hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14 ; voisin précédent : hash 0x097ae3f842959999b67d2ceb971d94c58279b42b04a5fca1bd47d09914080009 ; voisin suivant : hash 0x74f7dd908e35792023f6238ff1bc8999a0a24a7b025d65d58a810ac5701f9eb5 ; approbation[0] : hash 0x097ae3f842959999b67d2ceb971d94c58279b42b04a5fca1bd47d09914080009" },
    { "id": "E-8", "controls": [6], "status": "reussi", "reason": null, "admitted": null, "detail": "evenement : signature valide sous rec-test-01 ; voisin précédent : signature valide sous rec-test-01 ; voisin suivant : signature valide sous rec-test-01 ; approbation[0] : signature valide sous rec-test-01" },
    { "id": "E-9", "controls": [7], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-10", "controls": [6], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "E-11", "controls": [6], "status": "reussi", "reason": null, "admitted": null, "detail": null },
    { "id": "C-1", "controls": [2], "status": "reussi", "reason": null, "admitted": null, "detail": "previous seq 6, next seq 8" },
    { "id": "C-2", "controls": [2], "status": "reussi", "reason": null, "admitted": null, "detail": "chaînage avec les voisins fournis" },
    { "id": "C-3", "controls": [6], "status": "reussi", "reason": null, "admitted": null, "detail": "clé rec-test-01" },
    { "id": "M-1", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "leaf_hash 0x909a24597a9e9e7ccea41d80a270b0c6f86aad3a8a41462a5566afbe808103d9" },
    { "id": "M-2", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "chemin de 4 nœud(s) mène à la racine (indice 6, taille 9)" },
    { "id": "M-3", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "chemin cohérent avec le manifeste" },
    { "id": "P-1", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "période [1793869200, 1793872800), seq 1..9" },
    { "id": "P-2", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "événement dans la période" },
    { "id": "P-3", "controls": [2, 3], "status": "reussi", "reason": null, "admitted": null, "detail": "voisins cohérents avec la période" },
    { "id": "P-4", "controls": [3], "status": "reussi", "reason": null, "admitted": null, "detail": "count 9, racine 0xb16c288f2864e5e311646bc4af84e2752f0fe1f71266841ce65ddb28fa21298b" },
    { "id": "P-5", "controls": [3, 6], "status": "reussi", "reason": null, "admitted": null, "detail": "periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 signé par rec-test-02" },
    { "id": "A-1", "controls": [7], "status": "reussi", "reason": null, "admitted": null, "detail": "ticket apr-2201" },
    { "id": "A-2", "controls": [7], "status": "reussi", "reason": null, "admitted": null, "detail": "1 événement(s) de décision cohérent(s)" },
    { "id": "A-3", "controls": [7], "status": "reussi", "reason": null, "admitted": null, "detail": "2 approbateur(s) distinct(s) sur un seuil de 2/3" },
    { "id": "A-4", "controls": [7], "status": "non_execute", "reason": "piece_hors_dossier", "admitted": true, "detail": "événement de demande (request_hash 0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d) absent du dossier : non vérifiable" },
    { "id": "T-1", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "TimeStampToken DER : ContentInfo id-signedData, SignedData version 3, un seul SignerInfo, eContentType id-ct-TSTInfo" },
    { "id": "T-2", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "messageImprint SHA-256 égal au periodHash recalculé 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914" },
    { "id": "T-3", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "attributs signés : content-type, message-digest égal à l'empreinte de eContent, signingCertificateV2" },
    { "id": "T-4", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "certificat signataire « CN=TSA de test CT-6 » désigné par ESSCertIDv2 (SHA-256 0x0059fa87b4b02432ab3c2cbedbabaefe0e4b4839352921385c6fb1df1035c3a9)" },
    { "id": "T-5", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "algorithmes admis : SHA-256, sha256WithRSAEncryption, RSA 3072 bits" },
    { "id": "T-6", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "signature valide sur les attributs signés" },
    { "id": "T-7", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "chemin « CN=TSA de test CT-6 » → « CN=AC de test CT-6 » (/tsa_authorities/0), valide à genTime 2026-11-05T10:00:05Z, politique 1.3.6.1.4.1.99999.1.1 admise par l'ancre" },
    { "id": "T-8", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "extendedKeyUsage critique réduit à id-kp-timeStamping" },
    { "id": "T-9", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "TSTInfo version 1, politique 1.3.6.1.4.1.99999.1.1, genTime 2026-11-05T10:00:05Z, précision 1 s, numéro de série 0x01" },
    { "id": "T-10", "controls": [4], "status": "reussi", "reason": null, "admitted": null, "detail": "CRL de l'ancre (/revocation/crls/0, thisUpdate 2026-11-06T00:00:00Z, postérieure à genTime) : certificat de la TSA non révoqué" },
    { "id": "T-11", "controls": [4], "status": "non_execute", "reason": "ancre_absente", "admitted": true, "detail": "l'ancre /tsa_authorities/0 ne déclare aucun statut qualifié" },
    { "id": "O-1", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "en-tête magique, version 01, opération de fichier 08, arbre conforme, fin de fichier exacte" },
    { "id": "O-2", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "empreinte du fichier égale au periodHash recalculé 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914" },
    { "id": "O-3", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "opérations rejouées, toutes du profil f0, f1, 08 ; résultat de 32 octets" },
    { "id": "O-4", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "attestation Bitcoin de hauteur 1001 : résultat égal aux octets 36 à 67 de l'en-tête 1001" },
    { "id": "O-5", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "en-têtes 990 à 1020 du réseau regtest rattachés au point de contrôle 1000 de l'ancre (/bitcoin) ; preuve de travail sous la cible de nBits 0x207fffff vérifiée" },
    { "id": "O-6", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "profondeur k = 20, au moins min_confirmations = 6" },
    { "id": "O-7", "controls": [5], "status": "reussi", "reason": null, "admitted": null, "detail": "une attestation Bitcoin, aucune attestation en attente" },
    { "id": "R-1", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "registre.json (4 entrées) et certificat-commit.json (4 certificats) conformes et appariés" },
    { "id": "R-2", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "jeu de l'ancre /registry/validator_sets/0 (hauteurs 1 et suivantes) : hachage 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 égal au valsetHash des 4 certificats" },
    { "id": "R-3", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "validateurs.json déclare le jeu de valsetHash de chacun des 4 certificats" },
    { "id": "R-4", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "chainId noortrace-2124-dev égal à celui de l'ancre, pour les 4 certificats" },
    { "id": "R-5", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "4 certificats : proposition et precommits valides, au moins 3 signataires distincts, quorum 3 sur 4" },
    { "id": "R-6", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "BFTBlockHash recalculé égal au blockHash certifié et à block.hash, pour les 4 blocs" },
    { "id": "R-7", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "receiptsRoot recalculé égal à celui de l'en-tête, pour les 4 blocs" },
    { "id": "R-8", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "journaux émis par RecorderRegistry, AttestationRegistry et PeriodRegistry aux adresses de l'ancre" },
    { "id": "R-9", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "PeriodSubmitted : periodHash, org_id, journal_id, root, bornes et version égaux au manifeste, publishedAt égal à l'horodatage du bloc ; Anchored : empreinte 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 = keccak256(org_id ‖ journal_id ‖ periodHash), docType de période" },
    { "id": "R-10", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "RecorderRegistered aux blocs 16648 et 16652 : rec-test-01 et rec-test-02 de cles.json ; rec-test-02, clé du manifeste, inscrite sous 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, émetteur de l'ancre" },
    { "id": "N-3", "controls": [6], "status": "reussi", "reason": null, "admitted": null, "detail": "rec-test-01 et rec-test-02 de cles.json égales aux clés de l'ancre (/recorders/0, /recorders/1)" },
    { "id": "N-4", "controls": [8], "status": "reussi", "reason": null, "admitted": null, "detail": "émetteur de l'ancre 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49 égal à la chain_key de rec-test-02 dans l'ancre (/recorders/1)" }
  ],
  "failed_checks": [],
  "blocking_unexecuted": [],
  "absent_parts": [],
  "warnings": [
    { "id": "AV-O-3", "check": "O-5", "detail": "réseau regtest : réseau d'essai, sans valeur probante hors des tests" }
  ],
  "facts": {
    "recorder_keys": {
      "event_key_id": "rec-test-01",
      "manifest_key_id": "rec-test-02",
      "source": "ancres",
      "event_key_source": "ancres",
      "manifest_key_source": "ancres"
    },
    "approval": {
      "decision": "approuve",
      "ticket": "apr-2201",
      "approvers": ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"],
      "required": 2,
      "size": 3,
      "set_source": "dossier"
    },
    "timestamp": {
      "authority": "AC de test CT-6",
      "tsu_certificate_sha256": "0x0059fa87b4b02432ab3c2cbedbabaefe0e4b4839352921385c6fb1df1035c3a9",
      "tsu_subject_cn": "TSA de test CT-6",
      "gen_time": "2026-11-05T10:00:05Z",
      "accuracy": {
        "seconds": 1,
        "millis": null,
        "micros": null
      },
      "upper_bound": "2026-11-05T10:00:06Z",
      "policy": "1.3.6.1.4.1.99999.1.1",
      "serial_number": "0x01",
      "digest_algorithm": "sha256",
      "signature_algorithm": "sha256WithRSAEncryption",
      "key_bits": 3072,
      "qualified_claim": false,
      "qualified": null,
      "revocation": [
        {
          "certificate_sha256": "0x0059fa87b4b02432ab3c2cbedbabaefe0e4b4839352921385c6fb1df1035c3a9",
          "evidence": "crl",
          "issued_at": "2026-11-06T00:00:00Z"
        }
      ]
    },
    "bitcoin": {
      "file_digest": "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914",
      "network": "regtest",
      "checkpoint": {
        "height": 1000,
        "hash": "0x30f16c707dbc79c93c3d9d5279170f623d3f0d691735c0670ea90bb16087b3a0"
      },
      "attestations": [
        { "kind": "bitcoin", "height": 1001, "uri": null, "tag": null, "status": "reussi" }
      ],
      "retained_height": 1001,
      "block_hash": "0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026",
      "block_time": "2026-11-05T13:50:00Z",
      "median_bound": "2026-11-05T14:50:00Z",
      "confirmations": 20,
      "cumulative_work": "40"
    },
    "registry": {
      "chain_id": "noortrace-2124-dev",
      "entries": [
        {
          "role": "inscription",
          "block_number": 16648,
          "block_hash": "0x73f5b9980d64ce2b8c63d20d3590281cf09eec86a980fe4293eca4157fcc2da2",
          "block_time": "2026-10-22T22:20:38Z",
          "transaction_index": 0,
          "transaction_hash_declared": "0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158",
          "emitter": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
          "event": {
            "name": "RecorderRegistered",
            "orgId": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
            "chainKey": "0xaa2a59656361352e96ef2eed355316ef8b29dab7",
            "journalId": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
            "ed25519PubKey": "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
            "publisher": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
          }
        },
        {
          "role": "inscription",
          "block_number": 16652,
          "block_hash": "0x73483f231f12206f373d70201b0be12ec5610f14ebf7745a64e2e19c18f7f27d",
          "block_time": "2026-10-22T22:20:41Z",
          "transaction_index": 0,
          "transaction_hash_declared": "0x158850e1aae6d6a6eb7125387c581d580886135a7fafbe871e4185b66beea062",
          "emitter": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
          "event": {
            "name": "RecorderRegistered",
            "orgId": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
            "chainKey": "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49",
            "journalId": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
            "ed25519PubKey": "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
            "publisher": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
          }
        },
        {
          "role": "ancre",
          "block_number": 16660,
          "block_hash": "0x1e371008e09681b8a3d5a1b5515f1271bafbd418950488692608f2c500b861ee",
          "block_time": "2026-10-22T22:20:49Z",
          "transaction_index": 0,
          "transaction_hash_declared": "0x70edd263160e4fcd6c6887ac21daf4556720ef662facdf9bb12292366f120779",
          "emitter": "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8",
          "event": {
            "name": "Anchored",
            "fingerprint": "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6",
            "issuer": "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49",
            "docType": "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee"
          }
        },
        {
          "role": "cloture",
          "block_number": 16668,
          "block_hash": "0xe59edea93690470f375dc54ef19cb6c69d1ed5e916bdd7a5f810e10f4e375d3e",
          "block_time": "2026-10-22T22:20:56Z",
          "transaction_index": 0,
          "transaction_hash_declared": "0xd9fb0d69567fa4f5ecbf51179198fa02f30524a3275678405cfc11307374bbc0",
          "emitter": "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
          "event": {
            "name": "PeriodSubmitted",
            "id": 5,
            "periodHash": "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914",
            "orgId": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
            "journalId": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
            "root": "0xb16c288f2864e5e311646bc4af84e2752f0fe1f71266841ce65ddb28fa21298b",
            "periodStart": 1793869200,
            "periodEnd": 1793872800,
            "firstSeq": 1,
            "lastSeq": 9,
            "version": 0,
            "publisher": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "uri": "",
            "publishedAt": 1792707656
          }
        }
      ],
      "certificates": [
        {
          "height": 16648,
          "valset_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
          "set_source": "validators.json du réseau de développement, clés publiques seulement",
          "set_size": 4,
          "quorum": 3,
          "signers": ["v1", "v3", "v4"]
        },
        {
          "height": 16652,
          "valset_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
          "set_source": "validators.json du réseau de développement, clés publiques seulement",
          "set_size": 4,
          "quorum": 3,
          "signers": ["v1", "v3", "v4"]
        },
        {
          "height": 16660,
          "valset_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
          "set_source": "validators.json du réseau de développement, clés publiques seulement",
          "set_size": 4,
          "quorum": 3,
          "signers": ["v1", "v3", "v4"]
        },
        {
          "height": 16668,
          "valset_hash": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
          "set_source": "validators.json du réseau de développement, clés publiques seulement",
          "set_size": 4,
          "quorum": 3,
          "signers": ["v1", "v3", "v4"]
        }
      ]
    }
  },
  "verdict": "valide",
  "exit_code": 0,
  "statement": {
    "fr": "L'événement seq 7 (hachage 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) du journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 de l'organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres ; l'événement a été approuvé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait au plus tard le 2026-11-05T10:00:06Z UTC ; le manifeste d'empreinte 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existait avant la création du bloc Bitcoin 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante) ; sur le registre noortrace-2124-dev, la clôture de cette période (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) figure au bloc 16668 (heure déclarée par le bloc : 2026-10-22T22:20:56Z UTC), émise par le contrat PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, et son ancre 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 au bloc 16660 (heure déclarée 2026-10-22T22:20:49Z UTC), émise par AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 pour l'émetteur 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, clé de chaîne inscrite au bloc 16652 pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 que le réviseur déclare (validators.json du réseau de développement, clés publiques seulement).",
    "en": "Event seq 7 (hash 0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14) of journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164 of organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab is well-formed, chained to its neighbours seq 6 and 8 and included in the period from 2026-11-05T09:00:00Z to 2026-11-05T10:00:00Z closed by manifest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914; the event is signed by recorder key rec-test-01 and the manifest by key rec-test-02, keys given by the anchors file; the event was approved by 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 and 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, threshold 2 of 3 of the set declared by the dossier); according to AC de test CT-6 (unit TSA de test CT-6), the manifest with digest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existed no later than 2026-11-05T10:00:06Z UTC; the manifest with digest 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 existed before Bitcoin block 1001 (0x474467b4a5679ac228b840b99c9943f84f1c439537db877bac325061ac7d3026, regtest network) was created, under 20 blocks whose work connects to the reviewer's checkpoint 1000; time written by the miner: 2026-11-05T13:50:00Z UTC, accuracy not guaranteed by the protocol; bound under assumption: 2026-11-05T14:50:00Z UTC (test network, no evidential value); on registry noortrace-2124-dev, the closing of this period (organisation 0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab, journal 0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164) is in block 16668 (time declared by the block: 2026-10-22T22:20:56Z UTC), emitted by contract PeriodRegistry 0x4ee6ecad1c2dae9f525404de8555724e3c35d07b, and its anchor 0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6 in block 16660 (declared time 2026-10-22T22:20:49Z UTC), emitted by AttestationRegistry 0xf4b146fba71f41e0592668ffbf264f1d186b2ca8 for issuer 0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49, chain key registered in block 16652 for recorder key rec-test-02, which the reviewer holds as the chain key of rec-test-02; each of these blocks is signed by 3 of the 4 validators of set 0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751 declared by the reviewer (validators.json du réseau de développement, clés publiques seulement)."
  },
  "bound": null
}
```

Rapport d'erreur d'un répertoire sans `dossier.json` (code 2) :

<!-- schema: rapport-verification -->
```json
{
  "format": "noortrace/rapport-verification",
  "version": 0,
  "verifier": {
    "name": "scripts/verify/dossier.mjs",
    "implementation": "reference_javascript",
    "version": "0.1.0",
    "runtime": "node v22.22.0",
    "schemas": [
      { "id": "https://noortrace.example/schemas/v0/evenement.schema.json", "sha256": "0xcd2efffae72ebe2d00459ac643785415ad25d138325681aca6127a0a2fa0393f" },
      { "id": "https://noortrace.example/schemas/v0/manifeste.schema.json", "sha256": "0x1341dd18b1cc4b570c13ed4010228b13b78d1582292ea7ecba0ce1ac7a462bf2" },
      { "id": "https://noortrace.example/schemas/v0/dossier.schema.json", "sha256": "0xeca29ac0c6329e4434529dd07d82e2a93fd897fe875e7812b04f5734d9dc8fe5" },
      { "id": "https://noortrace.example/schemas/v0/registre.schema.json", "sha256": "0xcd9fff826267865fe43d37bb4a42bb3f0ba0d04d56be0fff67d306e5960131c8" },
      { "id": "https://noortrace.example/schemas/v0/validateurs.schema.json", "sha256": "0x233e7ee41d597119c9319382eacc673f316fe891f8e271cc1032a183972825fd" },
      { "id": "https://noortrace.example/schemas/v0/ancres-confiance.schema.json", "sha256": "0x1ab686a61d7dad8ea8e1d26b69e750e414b19e819f9a3516cb1d7c737c807d04" },
      { "id": "https://noortrace.example/schemas/v0/entetes-bitcoin.schema.json", "sha256": "0x77e991e484add0e308291578d8576c28a4264b5d2b2ae2c06b6832b470b6308c" },
      { "id": "https://noortrace.example/schemas/v0/rapport-verification.schema.json", "sha256": "0x4ade757ae8ecc1c9ae3bd6d32f33700349ffd0484862719f12ab808265109c55" }
    ]
  },
  "language": "fr",
  "inputs": {
    "dossier": {
      "path": "/home/reviseur/dossiers/vide",
      "index_sha256": null
    },
    "anchors": null,
    "bitcoin_headers": null,
    "second_manifest": null,
    "pieces": null,
    "required_controls": []
  },
  "verdict": null,
  "exit_code": 2,
  "error": {
    "kind": "dossier_illisible",
    "message": "dossier.json absent : le répertoire n'est pas un dossier de preuve",
    "check": null
  }
}
```

Validation d'un rapport :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/rapport-verification-v0.schema.json -d rapport.json
```

## 9. Contrôle 4 : jeton d'horodatage RFC 3161

### 9.1 Ce qui est horodaté : `periodHash`

Les trois ancres d'une période (contrôles 4, 5 et 8) portent sur une seule
valeur, `periodHash` = SHA-256(`P_M` ‖ `C_M`) de CT-1 §10.2. La donnée
horodatée est la suite d'octets `P_M ‖ C_M`, le **manifeste préfixé** ; sa
seule empreinte est `periodHash`.

**EX-9.1** Le `messageImprint` du jeton DOIT désigner l'algorithme SHA-256, et
son `hashedMessage` DOIT être `periodHash`. Le vérificateur recalcule
`periodHash` depuis `manifeste.json` selon CT-1 §10.2 ; il ne le lit jamais
dans `manifeste.sig`, dans `dossier.json` ni dans une autre partie.

Justification. Le manifeste engage la racine `R`, les bornes de la période
(`period_start`, `period_end`, `first_seq`, `last_seq`, `count`), la continuité
avec la période précédente (`prev_period_hash`), le journal (`org_id`,
`journal_id`) et la clé qui le signe (`recorder_key_id`). Horodater `R` seul
n'engage que `R` : deux périodes aux événements identiques ont la même racine,
toute période vide a la racine nulle (CT-1 §9.2), et rien ne relie alors
l'horodatage à un journal ni à des bornes. `PeriodRegistry` enregistre déjà
`periodHash`, et l'ancre d'`AttestationRegistry` est
`anchorFingerprint = keccak256(org_id ‖ journal_id ‖ periodHash)` (CT-1
§10.4) : une même valeur relie les trois ancres. Le manifeste porte un nonce
frais (CT-1 §10.1), donc deux manifestes, même de périodes aux événements
identiques, n'ont jamais la même empreinte, et un observateur ne peut pas
déduire de leurs jetons qu'ils portent sur la même donnée ; seuls des jetons
obtenus sur un même manifeste partagent l'empreinte (R1 F1.23, RFC 3161 §4
point 5, https://www.rfc-editor.org/rfc/rfc3161.txt). La TSA ne reçoit que
ces 32 octets et ne les examine pas (R1 F1.17, RFC 3161 §2.1).
L'architecture écrivait « SHA-256 de la racine » ; elle a été alignée
(section 16), comme CT-1 §11.2, §11.3 et §11.4, qui disent `periodHash`. En
cas d'écart, la règle de CT-6 prévaut.

### 9.2 Le fichier `jeton-rfc3161.der`

**EX-9.2** La partie `jeton_rfc3161` contient exactement un `TimeStampToken`
(RFC 3161 §2.4.2 : un `ContentInfo` dont le contenu est un `SignedData`, R1
F1.04) encodé selon le profil de lecture de 9.3, et rien d'autre. Une réponse
`TimeStampResp` (R1 F1.01) n'est pas un jeton : le fichier qui en contient une
échoue à T-1. Motif : le statut de la réponse n'a plus d'objet une fois le
jeton extrait, et une seule forme admise fait un seul analyseur. `openssl ts
-reply -token_out` produit cette forme (R1 F6.02,
https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/doc/man1/openssl-ts.pod.in).

**EX-9.3** Le fichier ne dépasse pas 64 Kio (EX-4.13) ; au-delà, il est
inexploitable et T-1 échoue.

### 9.3 Profil de lecture DER

**EX-9.4** Le vérificateur lit le jeton avec un lecteur DER borné : longueurs
définies sous forme minimale, numéros d'étiquette inférieurs à 31, `BOOLEAN`
codé `00` ou `ff`, `eContent` en `OCTET STRING` primitive, profondeur
d'imbrication au plus 32 (section 15), aucun octet après la fin d'une
structure qui n'en admet pas. Toute autre forme rend le jeton inexploitable
(T-1). Les règles de longueur et d'étiquette sont celles que `cryptobyte`
applique (R4 F5.05), et il a lu sans erreur un jeton qualifié réel (R4 F5.06) ;
la règle du `BOOLEAN` est celle du DER, qu'applique aussi `encoding/asn1`
(R4 F5.04).

Noms. Dans un `Name` d'un certificat ou d'une CRL (sujet, émetteur), du
jeton comme du fichier d'ancres, ainsi que dans `sid` et dans le champ `tsa`
de `TSTInfo`, une valeur `UTF8String` dont les octets ne sont pas de l'UTF-8
valide, ou une valeur `BMPString` de longueur impaire, rend l'objet
illisible : T-1 échoue pour le jeton ou l'un de ses certificats, et le
fichier d'ancres est inutilisable (N-1) pour l'un des siens. OpenSSL 3.0.13
refuse de lire un tel certificat et le jeton qui le porte (« invalid
utf8string », vecteur `t1-cn-utf8-invalide`, annexe A.8), et `crypto/x509` de
Go 1.24.7 le refuse aussi (`parseASN1String` et `parseName`,
`src/crypto/x509/parser.go`, lus). Une valeur d'un autre type de chaîne
(`UniversalString` par exemple) n'est pas décodée et ne rend pas l'objet
illisible : seul `tsu_subject_cn` peut en devenir `null` (EX-9.19).
`crypto/x509` refuse aussi un tel nom ; une implémentation en Go lit donc les
noms par sa propre relecture (EX-14.4).

**EX-9.21** Valeurs `DEFAULT` encodées (X.690 §11.5 interdit de les encoder) :
dans un certificat ou une CRL, du jeton comme du fichier d'ancres, un champ
`critical` d'extension encodé à `FALSE`, un champ `cA` de `basicConstraints`
encodé à `FALSE` et une `version` de certificat encodée à `v1` (`a0 03 02 01
00`) rendent l'objet illisible : T-1 échoue pour un certificat du jeton, et
le fichier d'ancres est inutilisable (N-1) pour l'un des siens. La même
règle vaut pour `ordering` encodé à `FALSE` dans `TSTInfo` (T-1). Deux
tolérances seulement, chacune signalée par AV-T-1 : `critical` encodé à
`FALSE` dans une extension de `TSTInfo` (EX-9.5), et `hashAlgorithm` encodé à
SHA-256 dans le premier `ESSCertIDv2` (valeur `DEFAULT` de RFC 5035 §4).
Motif : une seule lecture, la même pour toutes les implémentations ;
`crypto/x509` de Go accepte un `critical` encodé à `FALSE`, d'où la relecture
stricte qu'impose EX-14.4.

**EX-9.5** Tolérance dans `TSTInfo` (la première des deux que EX-9.21
admet ; la seconde porte sur `hashAlgorithm` dans le premier `ESSCertIDv2`) :
dans une `Extension` des `extensions` de `TSTInfo`, un champ `critical`
encodé explicitement à `FALSE` (`01 01 00`) est accepté et signalé par
l'avertissement AV-T-1. Un jeton qualifié réel (Sectigo) est ainsi encodé
alors que X.690 §11.5 interdit d'encoder une valeur `DEFAULT` (R1 F7.04,
F2.12) : un lecteur strict rejetterait un jeton valide.

**EX-9.6** Le vérificateur ne réencode jamais : les empreintes et les
signatures portent sur les octets tels que reçus (R1 F2.08, F2.09 ; RFC 5652
§5.4, https://www.rfc-editor.org/rfc/rfc5652.txt). Les propriétés DER qui ne
changent aucune valeur lue (ordre des `SET OF`, forme minimale des `INTEGER`)
ne sont pas contrôlées en version 0 ; les valeurs `DEFAULT` encodées suivent
EX-9.21.

### 9.4 Identifiants

| Nom | OID | Source |
|---|---|---|
| `id-signedData` | 1.2.840.113549.1.7.2 | R1 F2.01 (RFC 5652 §5.1) |
| `id-ct-TSTInfo` | 1.2.840.113549.1.9.16.1.4 | R1 F1.04 (RFC 3161 §2.4.2) |
| attribut `content-type` | 1.2.840.113549.1.9.3 | R1 F2.10 (RFC 5652 §11.1) |
| attribut `message-digest` | 1.2.840.113549.1.9.4 | R1 F2.11 (RFC 5652 §11.2) |
| attribut `signingCertificate` (ESS v1) | 1.2.840.113549.1.9.16.2.12 | R1 F1.29 (RFC 2634 §5.4, https://www.rfc-editor.org/rfc/rfc2634.txt) |
| attribut `signingCertificateV2` | 1.2.840.113549.1.9.16.2.47 | R1 F1.27 (RFC 5035 §3, https://www.rfc-editor.org/rfc/rfc5035.txt) |
| SHA-256, SHA-384, SHA-512 | 2.16.840.1.101.3.4.2.1, …2.2, …2.3 | R1 F2.15 (RFC 5754 §2, https://www.rfc-editor.org/rfc/rfc5754.txt) |
| `rsaEncryption` | 1.2.840.113549.1.1.1 | R1 F2.14 (RFC 3370 §3.2, https://www.rfc-editor.org/rfc/rfc3370.txt) |
| `sha256WithRSAEncryption`, `sha384…`, `sha512…` | 1.2.840.113549.1.1.11, …1.12, …1.13 | RFC 5754 §3.2 |
| `id-RSASSA-PSS` | 1.2.840.113549.1.1.10 | RFC 4056 §2 (https://www.rfc-editor.org/rfc/rfc4056.txt) |
| `ecdsa-with-SHA256`, `…SHA384`, `…SHA512` | 1.2.840.10045.4.3.2, …3.3, …3.4 | RFC 5754 §3.3 |
| courbes P-256, P-384, P-521 | 1.2.840.10045.3.1.7, 1.3.132.0.34, 1.3.132.0.35 | octets `06 08 2a 86 48 ce 3d 03 01 07`, `06 05 2b 81 04 00 22`, `06 05 2b 81 04 00 23` rendus par `openssl ecparam -name <courbe> -outform DER` (OpenSSL 3.0.13) |
| `id-kp-timeStamping` | 1.3.6.1.5.5.7.3.8 | R1 F1.18 (RFC 3161 §2.3) |
| `qcStatements`, `esi4-qtstStatement-1` | 1.3.6.1.5.5.7.1.3, 0.4.0.19422.1.1 | R1 F3.11 (EN 319 422 annexe B, https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf) |
| `subjectKeyIdentifier`, `keyUsage`, `basicConstraints`, `extKeyUsage` | 2.5.29.14, 2.5.29.15, 2.5.29.19, 2.5.29.37 | RFC 5280 §4.2.1 (https://www.rfc-editor.org/rfc/rfc5280.txt, copie du digest R1) |
| `cRLReasons`, `deltaCRLIndicator`, `issuingDistributionPoint` | 2.5.29.21, 2.5.29.27, 2.5.29.28 | RFC 5280 §5.2, §5.3 |

### 9.5 Vérifications T-1 à T-11

| Id | Vérification | En anglais | Ancre nécessaire | Exécutée si |
|---|---|---|---|---|
| T-1 | Structure du jeton | token structure | non | partie présente |
| T-2 | Empreinte = `periodHash` | imprint = `periodHash` | non | T-1 réussie, `manifeste.json` exploitable (P-1) |
| T-3 | Attributs signés | signed attributes | non | T-1 réussie |
| T-4 | Certificat signataire identifié | signer certificate identified | non (oui si le jeton ne porte pas le certificat) | T-1 réussie |
| T-5 | Algorithmes admis | admitted algorithms | non | T-4 réussie |
| T-6 | Signature | signature | non | T-5 réussie |
| T-7 | Chemin de certification jusqu'à une autorité de l'ancre, à `genTime` | certification path to an anchor authority, at `genTime` | oui | T-4, T-6 et T-9 réussies |
| T-8 | Usage horodatage du certificat signataire | time-stamping usage of the signer certificate | non | T-4 réussie |
| T-9 | Contenu de `TSTInfo` | `TSTInfo` content | non | T-1 réussie ; pour la règle 3, quand `tsa` est un `directoryName`, aussi T-4 réussie, sinon T-9, si ses autres règles tiennent, est `non_execute` avec la raison qu'elle hérite de T-4 (EX-5.5, EX-9.15) |
| T-10 | Révocation | revocation | oui | T-7 réussie (donc T-6) |
| T-11 | Statut qualifié déclaré par l'ancre | qualified status declared by the anchor | oui | T-7 réussie |

Une vérification dont la condition « exécutée si » n'est pas remplie parce
qu'une vérification préalable a échoué est `non_execute`, raison
`prerequis_en_echec` (EX-5.5) ; le contrôle a déjà échoué. Si la vérification
préalable n'a pas été exécutée pour une raison admise, elle en reprend la
raison (EX-5.5). Une vérification qui exige une ancre absente est
`non_execute` avec la raison `ancre_absente`.
Sans fichier d'ancres, T-1 à T-3 s'exécutent quand même. T-4 aussi quand le
jeton porte le certificat signataire, et, si T-4 réussit, T-5, T-6 et T-8.
T-9 aussi, sauf quand `tsa` est un `directoryName` et que T-4 n'a pas
réussi : si ses autres règles tiennent, T-9 prend alors la raison qu'elle
hérite de T-4 (EX-9.15). Un jeton qui n'horodate pas ce manifeste échoue
sans qu'aucune ancre soit nécessaire.
T-7, T-10 et T-11 exigent T-6 réussie : sans signature vérifiée, `genTime`
n'est pas authentifié, et un chemin valide à cet instant ne prouverait rien.

**EX-9.7 (T-1, structure)** Le fichier est un `ContentInfo` dont
`contentType` = `id-signedData` et dont `content [0] EXPLICIT` est un
`SignedData` ; aucun octet ne suit le `ContentInfo`. Le `SignedData` a
`version` = 3 (R1 F2.02), un `encapContentInfo` dont `eContentType` =
`id-ct-TSTInfo` et dont `eContent` est présent, au plus 16 certificats dans
`certificates` (des `Certificate` X.509, rien d'autre), et exactement un
`SignerInfo` (R1 F1.05, F5.11). Le `SignerInfo` a `version` 1 avec `sid` =
`issuerAndSerialNumber`, ou `version` 3 avec `sid` = `subjectKeyIdentifier
[0]` (R1 F2.06), et porte `signedAttrs` (R1 F2.07). Les octets de valeur de
`eContent` sont un `TSTInfo` complet, sans octet en trop, dont `version` = 1
(R1 F1.06). Toute défaillance de lecture selon 9.3 met T-1 en échec.

**EX-9.8 (T-2, empreinte)** Dans `messageImprint`, `hashAlgorithm.algorithm`
= SHA-256 (2.16.840.1.101.3.4.2.1), paramètres absents ou `NULL` (`05 00`)
(R1 F2.15) ; les octets de valeur de `hashedMessage` sont exactement les 32
octets de `periodHash`. Toute autre valeur, longueur ou algorithme : échec.

**EX-9.9 (T-3, attributs signés)** Dans `signedAttrs`, chaque type d'attribut
figure au plus une fois et a exactement une valeur ; `content-type` est
présent et vaut `id-ct-TSTInfo` (R1 F2.09, F2.10) ; `message-digest` est
présent et ses octets égalent l'empreinte, par `SignerInfo.digestAlgorithm`,
des seuls octets de valeur de `eContent` (sans étiquette ni longueur, R1
F2.08, F2.11) ; `signingCertificate` ou `signingCertificateV2`, ou les deux,
sont présents (R1 F1.05, F1.26). T-3 calcule l'empreinte pour MD5, SHA-1,
SHA-224, SHA-256, SHA-384 et SHA-512, que T-5 admette la fonction ou non
(T-5 juge seule l'admission) ; pour tout autre `digestAlgorithm`, l'empreinte
n'est pas calculable et T-3 échoue.

**EX-9.10 (T-4, certificat signataire)** Les candidats sont les certificats du
champ `certificates` du jeton, puis ceux de l'ancre (`certificate` et
`intermediates` des autorités, section 12). Le certificat signataire `S` est
le candidat que désigne `sid` : `issuerAndSerialNumber` dont l'`issuer` égale
octet pour octet le `Name` émetteur du candidat et dont le numéro égale le
sien, ou `subjectKeyIdentifier` égal à la valeur de son extension 2.5.29.14.
Aucun candidat désigné : `non_execute` (`ancre_absente`) ; le certificat n'est
ni dans le jeton ni dans l'ancre, et le réviseur peut l'y ajouter
(`intermediates`). Plusieurs candidats distincts désignés : `echoue`. Puis,
pour `S` :

1. si `signingCertificate` est présent, le `certHash` de son premier
   `ESSCertID` égale SHA-1 du DER complet de `S` (R1 F1.29) ;
2. si `signingCertificateV2` est présent, le `certHash` de son premier
   `ESSCertIDv2` égale l'empreinte du DER complet de `S` par son
   `hashAlgorithm` (SHA-256 s'il est absent ; errata 2364 de RFC 5035 : la
   fonction est celle de `hashAlgorithm`, R1 F1.27, F1.28) ;
3. `issuerSerial`, s'il est présent dans ce premier identifiant, porte un
   `directoryName` égal octet pour octet à l'émetteur de `S` et le numéro de
   `S`.

Une règle non satisfaite : `echoue` ; une empreinte qui ne correspond pas au
certificat qui vérifie la signature rend celle-ci invalide (RFC 5035,
R1 F1.27). SHA-1 n'est admis qu'ici, comme identifiant de certificat : le
jeton qualifié réel de Sectigo ne porte que `signingCertificate` en SHA-1
(R1 F7.03).

**EX-9.11 (T-5, algorithmes)** Sont admis :

| Élément | Admis | Refusé (`echoue`) | Hors version 0 (`non_execute`, `hors_perimetre_version`) |
|---|---|---|---|
| `SignerInfo.digestAlgorithm` | SHA-256, SHA-384, SHA-512, paramètres absents ou `NULL` | toute autre fonction, dont SHA-1 et MD5 | — |
| `SignerInfo.signatureAlgorithm` | `rsaEncryption` (paramètres `NULL` ou absents) ; `sha256/384/512WithRSAEncryption` dont la fonction égale `digestAlgorithm` ; `id-RSASSA-PSS` dont `hashAlgorithm` égale `digestAlgorithm` (RFC 4056 §3) et dont `maskGenAlgorithm` est MGF1 avec la même fonction, `trailerField` = 1 (choix de cette spécification) ; `ecdsa-with-SHA256/384/512` dont la fonction égale `digestAlgorithm` | une signature RSA ou ECDSA sur SHA-1 ou MD5 ; des paramètres contraires à la colonne de gauche | DSA, EdDSA, SLH-DSA, XMSS, LMS, tout autre identifiant |
| Clé publique de `S` | RSA de module ≥ 2048 bits ; ECDSA sur P-256, P-384 ou P-521 | RSA < 2048 bits | toute autre courbe ou type de clé |

`rsaEncryption` est admis parce que les implémentations CMS DOIVENT
l'accepter (R1 F2.14) et que le jeton qualifié réel de Sectigo et
`openssl ts` l'emploient (R1 F6.09, F7.03) ; RSASSA-PSS parce que le
certificat d'une AC d'horodatage reconnue, « Swisscom TSS CA 4 » de la liste
suisse, est signé en RSASSA-PSS (R1 F7.09), ce que la règle 3 de T-7 doit
admettre ; aucun jeton signé en PSS n'a été observé. ETSI TS 119 312 V2.1.1
exige des vérificateurs de jetons DSA, EdDSA, SLH-DSA, XMSS et LMS (R1 F3.06) :
la version 0 ne les couvre pas (section 17). Le seuil de 2048 bits est un
choix de cette spécification ; TS 119 312 fixe pour RSA de 1 900 à moins de
3 000 bits la fin de l'émission de nouveaux certificats après le 2026-12-31
et, pour ceux émis avant, une fin de validité au plus tard le 2028-12-31 (R1
F3.07) : règles d'émission, non de vérification. Le rapport porte
l'algorithme et la taille de clé.

**EX-9.12 (T-6, signature)** La signature de `SignerInfo` est vérifiée sous la
clé publique de `S` sur les octets DER de `signedAttrs` tels que reçus, dont
le premier octet `a0` (étiquette `[0] IMPLICIT`) est remplacé par `31`
(étiquette `SET OF`) (R1 F2.08 ; vérifié sur un jeton de test et sur le jeton
qualifié de Sectigo, R1 F2.17). RSA PKCS #1 v1.5 : la valeur a la longueur du
module ; ECDSA : la valeur est la structure DER `SEQUENCE { r, s }`. Échec de
vérification : `echoue`.

**EX-9.13 (T-7, chemin à `genTime`)** T-7 réussit s'il existe une suite
`S = c₀, c₁, …, cₙ` (n ≤ 4) de certificats pris parmi les candidats de T-4 et
une autorité `A` de l'ancre telles que :

1. ou bien `n = 0` et le DER de `S` égale celui du certificat de `A` (l'ancre
   désigne l'unité elle-même) ; ou bien le `Name` émetteur de `cₙ` égale octet
   pour octet le `Name` sujet du certificat de `A`, et la signature de `cₙ` se
   vérifie sous la clé publique de `A` ;
2. pour chaque `i < n`, l'émetteur de `cᵢ` égale octet pour octet le sujet de
   `cᵢ₊₁`, et la signature de `cᵢ` se vérifie sous la clé de `cᵢ₊₁` ;
3. chaque signature de certificat emploie un algorithme admis par T-5 ;
4. pour chaque `cᵢ` : `notBefore ≤ genTime ≤ notAfter`, bornes incluses
   (R1 F5.01) ;
5. pour chaque `cᵢ` avec `i ≥ 1` : `basicConstraints` présent, critique, `cA`
   vrai (R1 F5.03) ; `pathLenConstraint`, s'il est présent, vaut au moins
   `i − 1`, le nombre de certificats d'AC entre `cᵢ` et `S` ; `keyUsage`,
   s'il est présent, contient `keyCertSign` (bit 5) ;
6. aucun `cᵢ` ne porte d'extension critique autre que `basicConstraints`,
   `keyUsage` et `extKeyUsage` ;
7. `accepted_policies` de `A` est nul ou contient la `policy` du jeton.

Chemin retenu. Plusieurs autorités, et pour une autorité plusieurs chemins,
peuvent satisfaire ces règles (racine et intermédiaire, AC et unité épinglée).
Le vérificateur retient, de façon déterministe : la première autorité, dans
l'ordre de `tsa_authorities`, pour laquelle un chemin existe ; pour elle, le
chemin le plus court (`n = 0` d'abord, et pour `n = 0` l'identité de la
règle 1 avant la signature de `S` par `A`) ; à longueur égale, le premier dans l'ordre des candidats, comparés
certificat par certificat de `c₁` à `cₙ` (certificats du jeton dans leur ordre,
puis `certificate` et `intermediates` des autorités dans l'ordre du fichier).
T-10, T-11, `facts.timestamp.authority`, `anchors_used` et la proposition de
EX-9.20 portent sur ce chemin et cette autorité seulement.

Le certificat de l'ancre n'est pas lui-même validé : seuls sa clé publique et
son nom sujet servent, comme pour une identité de service d'une liste de
confiance (R1 F4.03, ETSI TS 119 612 §5.5.3,
https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf).
Ses dates ne sont pas comparées à `genTime`, sauf quand l'ancre désigne
l'unité elle-même (voir plus bas), et sa révocation n'est vue que si une CRL
du fichier d'ancres la porte (EX-9.16) : il revient au réviseur de choisir
une autorité valide, non révoquée et au statut voulu à `genTime` (H3, 12.5).
L'ancre peut donc être une AC intermédiaire, non auto-signée, ce
qu'`openssl ts -verify` n'accepte qu'avec `-partial_chain` (R1 F7.06). Quand
l'ancre désigne l'unité elle-même (n = 0, identité de la règle 1), son
certificat est aussi c₀ = S. Les règles 4 et 6 s'appliquent donc à lui, et
ses dates sont comparées à `genTime`. T-10 n'a alors aucun cᵢ à prouver, et
la révocation de ce certificat ne se voit que par une CRL du fichier d'ancres
(EX-9.16). L'instant de validation est `genTime`, jamais l'heure de la
vérification : RFC 5280 §6.1 admet une validation à un instant passé
(R1 F5.02) et ETSI TS 119 615 §4.3.4 fixe l'instant du jeton (R1 F4.06).
`genTime` est comparé à sa pleine précision (fraction comprise) ; `UTCTime`
d'un certificat se lit `20AA` pour `AA < 50`, `19AA` sinon (RFC 5280
§4.1.2.5, R1 F5.01). Sans fichier d'ancres ou sans autorité : `non_execute`
(`ancre_absente`). Des candidats existent mais aucun chemin ne satisfait les
sept règles : `echoue`.

**EX-9.14 (T-8, usage horodatage)** `S` porte l'extension `extKeyUsage`,
critique, avec exactement une valeur, `id-kp-timeStamping` (R1 F1.18 ;
exigence que `openssl ts` applique aussi, R1 F5.12, F6.02) ; `keyUsage`, s'il
est présent, est une partie non vide de {`digitalSignature` (bit 0),
`nonRepudiation` (bit 1)} : l'un, l'autre ou les deux (R1 F5.04, F5.12) ;
`basicConstraints` est absent ou `cA` faux.

**EX-9.15 (T-9, contenu de `TSTInfo`)**

1. `genTime` est un `GeneralizedTime` `AAAAMMJJhhmmss[.f…]Z`, fraction sans
   zéro final, date existante du calendrier grégorien proleptique, années
   0000 à 9999 lues telles quelles (R1 F1.11) ;
2. `accuracy`, s'il est présent, a `seconds` de 0 à 86 400 (une journée,
   borne de cette spécification), `millis` dans 1…999 et `micros` dans 1…999
   quand ils sont présents ; un sous-champ absent vaut zéro (R1 F1.12) ;
   `genTime` + `accuracy` ne dépasse pas `9999-12-31T23:59:59.999999Z` ; ces
   entiers sont lus sans limite de taille par T-1 et bornés ici ;
3. `tsa`, s'il est présent, est un `directoryName` égal octet pour octet au
   sujet de `S` (R1 F1.15) ; une autre forme de `GeneralName` n'est pas
   comparée en version 0 et lève AV-T-2 ;
4. aucune extension de `TSTInfo` n'est critique (EN 319 422 §5.2.2 l'interdit,
   R1 F3.03) ;
5. l'extension `qcStatements`, si elle est présente, est une `SEQUENCE OF
   QCStatement` bien formée ; elle est seulement lue (prétention, T-11).

`ordering` et `nonce` sont lus et rapportés, jamais contrôlés : le nonce ne se
contrôle qu'à l'acquisition, contre la requête (R1 F1.14, F1.16), ce qui
relève de CT-5 (section 13). `serialNumber` est accepté jusqu'à 160 bits
(R1 F1.10). Statut : `echoue` si l'une des règles 1, 2, 4 ou 5 ne tient pas,
ou si la règle 3 compare `tsa` au sujet de `S` et le trouve différent ; sinon,
quand `tsa` est un `directoryName` et que `S` n'est pas établi (T-4 n'a pas
réussi), la règle 3 n'est pas évaluée et T-9 est `non_execute` avec la raison
qu'elle hérite de T-4 (EX-5.5) ; sinon `reussi`.

**EX-9.16 (T-10, révocation)** Pour chaque certificat `cᵢ` du chemin retenu
par T-7 (le certificat de l'ancre exclu, traité plus bas), le vérificateur
cherche une **preuve de non-révocation** :

1. une liste de révocation (CRL, RFC 5280 §5) prise dans `revocation.crls` de
   l'ancre ou dans le champ `crls` du jeton (R1 F2.04), qui est complète
   (sans extension `deltaCRLIndicator` ni `issuingDistributionPoint`
   critique), dont l'émetteur égale octet pour octet l'émetteur de `cᵢ`, dont
   la signature se vérifie sous la clé du certificat qui suit `cᵢ` dans le
   chemin (ou de `A`) avec un algorithme admis par T-5, et dont `thisUpdate`
   est postérieur ou égal à `genTime` ;
2. ou une déclaration du réviseur (`revocation.statements` de l'ancre) dont
   `certificate_sha256` égale le SHA-256 du DER de `cᵢ` et dont
   `not_revoked_at` est postérieur ou égal à `genTime`.

Une CRL dont l'émetteur est celui d'un `cᵢ` mais qui ne remplit pas le reste
de la règle 1 n'est pas une preuve : elle est écartée et signale AV-T-3 ; une
CRL du jeton illisible aussi. Une CRL dont l'émetteur n'est celui d'aucun
certificat examiné (les `cᵢ` et celui de `A`) n'est pas consultée et ne lève
rien : un fichier d'ancres peut porter les CRL de plusieurs autorités. Si une
CRL retenue liste `cᵢ` (même numéro de série), la
révocation laisse le jeton valide si et seulement si l'entrée porte
`cRLReasons` égal à `unspecified` (0), `affiliationChanged` (3), `superseded`
(4) ou `cessationOfOperation` (5) **et** `revocationDate` est strictement
postérieure à `genTime` ; dans tout autre cas, dont l'absence de raison,
`keyCompromise` (1), `cACompromise` (2) et `certificateHold` (6), T-10 échoue.
Règle tirée de RFC 3161 §4 (R1 F1.21) ; les raisons 2, 6, 8, 9 et 10, que
RFC 3161 ne cite pas, sont traitées comme l'absence de raison.

Certificat de l'autorité `A`. Il n'a pas à être prouvé non révoqué : le
réviseur le choisit (H3). Mais si une CRL de `revocation.crls` du fichier
d'ancres, complète (sans `deltaCRLIndicator` ni `issuingDistributionPoint`
critique), a pour émetteur l'émetteur du certificat de `A` et liste son
numéro de série, cette révocation est jugée comme celle d'un `cᵢ` (raison
tolérée et date strictement postérieure à `genTime`, sinon T-10 échoue). La
signature de cette CRL n'est pas exigée : le réviseur l'a placée dans son
fichier, et elle ne peut que retirer la confiance qu'il accorde à son
autorité (12.1). Les CRL du jeton ne sont pas consultées pour le certificat
de `A`.

Statut : `echoue` si une CRL retenue disqualifie un `cᵢ`, ou si une CRL du
fichier d'ancres disqualifie le certificat de `A` ; sinon `reussi` si chaque
`cᵢ` a sa preuve (chemin réduit au certificat de l'ancre, `n = 0` identité :
rien à prouver, `reussi`) ; sinon `non_execute` (`ancre_absente`). Ce que T-10
ne voit pas : la révocation du certificat de `A` quand le fichier d'ancres ne
porte pas la CRL qui la publie, et la révocation d'une AC au-dessus de `A`
(7.2, 12.5).

`openssl ts -verify` ne peut pas servir d'oracle pour T-10 : il rejette toute
révocation, même postérieure à `genTime` et pour `superseded`, et refuse une
CRL postérieure à `-attime` (R1 F5.13, F5.14). La réponse OCSP n'est pas lue
par la version 0 ; un réviseur qui ne dispose que d'OCSP (cas des AC
d'horodatage de Swisscom, R1 F7.07) consigne son contrôle par une déclaration
(règle 2).

**EX-9.17 (T-11, statut qualifié)** T-11 réussit si l'autorité `A` retenue par
T-7 porte une déclaration `qualified` non nulle (section 12) dont l'intervalle
`[valid_from, valid_to]` contient `genTime` (`valid_to` nul : pas de borne
haute) ; sinon `non_execute` (`ancre_absente`). Le statut de T-11 n'entre pas
dans celui du contrôle 4 : il décide seulement si l'énoncé dit « qualifié »
(9.8). Le vérificateur ne détermine pas lui-même le statut qualifié ; le
réviseur l'établit et en écrit le résultat dans l'ancre. Pour `eidas`, la
partie utilisatrice est censée employer une liste de confiance de l'UE et
ETSI TS 119 615 (EN 319 421 §8.1 note 2, R1 F3.16), dont la procédure §4.6
détermine le statut d'un jeton (R1 F4.07,
https://www.etsi.org/deliver/etsi_TS/119600_119699/119615/01.02.01_60/ts_119615v010201p.pdf).
Pour `zertes`, cette procédure ne s'applique pas : un certificat dont le pays
n'est pas un État membre donne PROCESS_FAILED et le résultat « Indeterminate »
(TS 119 615 PRO-4.3.4-01, PRO-4.6.4-07) ; le réviseur lit la liste suisse
selon ses règles de schéma (type
`https://uri.tsl-switzerland.ch/TrstSvc/Svctype/TSA/QTST`, statut
« recognised », équivalent du « qualified » européen, R1 F4.09, F4.10). L'énoncé
`esi4-qtstStatement-1` des `extensions` du jeton n'est qu'une prétention (EN
319 421 §8.1 note 2, R1 F3.16) : il est rapporté (`qualified_claim`), jamais
pris pour une preuve. Le cadre (`eidas` ou `zertes`) est celui que l'ancre
déclare ; la liste suisse n'est pas dans la liste européenne et emploie ses
propres URI (R1 F4.08, F4.10), d'où deux valeurs distinctes.

### 9.6 Statut du contrôle 4

**EX-9.18** Partie `jeton_rfc3161` absente : contrôle 4 `non_execute`, avec
la raison de EX-4.3. Sinon : `echoue` si l'une de T-1 à T-10 échoue ; sinon
`non_execute` si l'une de T-1 à T-10 n'est pas exécutée, avec la raison que
choisit EX-6.5 ; sinon `reussi`. T-11 n'entre pas dans ce calcul.

### 9.7 Avertissements et valeurs rapportées

| Avertissement | Condition |
|---|---|
| AV-T-1 | Valeur `DEFAULT` encodée explicitement et tolérée : `critical` à `FALSE` dans une extension de `TSTInfo` (EX-9.5, vérification T-1), ou `hashAlgorithm` à SHA-256 dans le premier `ESSCertIDv2` (EX-9.21, vérification T-4). |
| AV-T-2 | Champ `tsa` sous une autre forme que `directoryName`, non comparé. |
| AV-T-3 | CRL écartée : émise pour un certificat du chemin mais à signature invalide, delta ou partielle, ou de `thisUpdate` antérieur à `genTime` ; ou CRL du jeton illisible (EX-9.16). Une CRL d'un autre émetteur n'est pas consultée et ne lève rien. |
| AV-T-4 | `ts` de l'événement prouvé (CT-1 §5) postérieur à `genTime` + `accuracy` : l'horloge de l'enregistreur avançait sur celle de la TSA, ou `ts` est faux. Avertissement seulement : une dérive d'horloge honnête de quelques secondes suffit à le lever. |

Un avertissement n'est jamais un échec et ne change aucun statut.

**EX-9.19** Pour le contrôle 4, le rapport (section 8) porte au moins :
`authority` (nom de l'autorité de l'ancre retenue), `tsu_certificate_sha256`,
`tsu_subject_cn` (valeur du premier attribut `commonName` du sujet de `S`,
`null` s'il n'en a pas ou s'il est d'un type de chaîne autre que
`UTF8String`, `PrintableString`, `IA5String`, `TeletexString`,
`NumericString` ou `BMPString` ; une `UTF8String` invalide ou une
`BMPString` de longueur impaire a déjà rendu le certificat illisible, EX-9.4),
`gen_time` (RFC 3339 UTC, fraction de `genTime`
conservée), `accuracy` (`{seconds, millis, micros}` ou `null`), `upper_bound`
(`genTime` + `accuracy`, RFC 3339 UTC), `policy` (OID), `serial_number`
(hexadécimal `0x`), `digest_algorithm`, `signature_algorithm`, `key_bits`,
`qualified_claim` (booléen), `qualified` (`{framework, source}` ou `null`),
`revocation` (liste `{certificate_sha256, evidence: "crl" | "declaration",
issued_at}`).

### 9.8 Énoncé produit

**EX-9.20** Quand le contrôle 4 réussit, il fournit à l'énoncé de la section 6
la proposition suivante, et aucune autre :

- français : « selon `<authority>` (unité `<tsu_subject_cn>`), le manifeste
  d'empreinte `<periodHash>` existait au plus tard le `<upper_bound>` UTC » ;
  suivi, si T-11 a réussi, de « ; horodatage qualifié `<eIDAS|ZertES>` selon
  le réviseur (`<source>`) » ;
- anglais : “according to `<authority>` (unit `<tsu_subject_cn>`), the
  manifest with digest `<periodHash>` existed no later than `<upper_bound>`
  UTC”, suivi de “; `<eIDAS|ZertES>` qualified timestamp according to the
  reviewer (`<source>`)”.

Quand `tsu_subject_cn` est `null`, `<tsu_subject_cn>` est remplacé par
`tsu_certificate_sha256`, le SHA-256 du DER de `S` (`0x…`). Sans `accuracy`,
« `<upper_bound>` UTC », avec son « UTC », est remplacé par « `<gen_time>`
UTC, à la précision près de la politique `<policy>`, que le jeton n'indique
pas ». En anglais, « `<upper_bound>` UTC » est remplacé par “`<gen_time>`
UTC, within the accuracy of policy `<policy>`, not stated in the token”. Ce
passage se termine donc par « n'indique pas » (“not stated in the token”),
sans second « UTC ». L'implémentation de référence suit cette règle, et
ses tests le vérifient. Sans `accuracy`, le jeton ne borne l'instant que par
d'autres moyens (R1 F1.12). Le jeton ne dit rien de qui l'a demandé
(R1 F1.17) ni de l'instant de production du manifeste (section 7).

## 10. Contrôle 5 : preuve OpenTimestamps

### 10.1 Ce qui est horodaté

**EX-10.1** L'empreinte de fichier de `preuve.ots` DOIT être `periodHash`, avec
l'opération de hachage de fichier SHA-256 (`08`). C'est exactement ce que
produit `ots stamp` appliqué à un fichier qui contient les octets `P_M ‖ C_M`
(le manifeste préfixé de 9.1) : l'outil hache les octets du fichier (R2-F02,
R2-F77). Contrôle 4 et contrôle 5 horodatent donc la même donnée.

### 10.2 Format de `preuve.ots`

Le format est celui de `opentimestamps.core`, déclaré « consensus-critical »
par ses auteurs (R2-F24,
https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/README.md).

| Élément | Octets | Règle |
|---|---|---|
| En-tête magique | 31 | `00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92 94` (R2-F01) |
| Version | 1 | `01` : seule version admise (1), que le `varuint` de la version publiée 0.4.5 et l'`uint8` de la branche principale encodent tous deux par cet octet, comme toute valeur inférieure à 128 ; c'est le seul octet de version que les deux lecteurs acceptent (R2-F04 à R2-F07) |
| Opération de hachage du fichier | 1 | `08` (SHA-256) |
| Empreinte du fichier | 32 | comparée par O-2 |
| Arbre | variable | grammaire ci-dessous |
| Fin | — | aucun octet après l'arbre (R2-F03, R2-F67) |

```text
arbre(m)     = *( ff branche(m) ) branche(m)          ; toutes les branches sauf la dernière précédées de ff
branche(m)   = 00 attestation                          ; feuille
             / op arbre(op(m))
op           = f0 varbytes(1..4096)                    ; append : m ‖ argument
             / f1 varbytes(1..4096)                    ; prepend : argument ‖ m
             / 08                                      ; sha256(m)
             / 02 / 03 / 67 / f2 / f3                  ; sha1, ripemd160, keccak256, reverse, hexlify : reconnues, hors profil v0
attestation  = étiquette(8 octets) varbytes(0..8192)
varbytes(a..b) = varuint(n) n octets, a ≤ n ≤ b
varuint      = LEB128 non signé, groupes de 7 bits, petit-boutiste, bit 0x80 = « suite »
```

Sources : codes d'opération et sémantique, R2-F10, R2-F12 ; branchements,
R2-F16 ; attestations, R2-F19 ; `varuint` et `varbytes`, R2-F06, R2-F08 ;
limites, R2-F13, R2-F18 (code de
https://github.com/opentimestamps/python-opentimestamps/tree/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core).

| Étiquette d'attestation | Charge utile | Nature |
|---|---|---|
| `05 88 96 0d 73 d7 19 01` | `varuint` de la hauteur du bloc, consommé exactement | Bitcoin (R2-F21) |
| `83 df e3 0d 2e f9 0c 8e` | `varbytes` d'une URI de 0 à 1000 octets pris dans `A-Z a-z 0-9 - . _ / :`, consommé exactement ; la bibliothèque de référence admet l'URI vide (`read_varbytes(MAX_URI_LENGTH)`, minimum 0, R2-F20) | en attente (R2-F20) |
| toute autre | opaque | inconnue (dont Litecoin et Ethereum, R2-F23) |

**EX-10.2** Lecture stricte, en plus de la grammaire : un `varuint` est sous
forme minimale (aucun groupe final nul après un groupe de suite) et tient en
9 octets au plus ; une hauteur Bitcoin est inférieure à 2³² ; un chemin de la
racine à une attestation compte au plus 255 opérations (la bibliothèque de
référence accepte 255 opérations imbriquées et en refuse 256, R2-F18,
R2-F67) ; le fichier ne dépasse pas 256 Kio (EX-4.13). La forme minimale
des `varuint` est plus stricte que `python-opentimestamps`, qui accepte une
forme non minimale sans borne (R2-F07, R2-F67) : le fichier étant figé par son
SHA-256 dans `dossier.json`, cette tolérance n'apporte rien et ouvre une
divergence entre analyseurs.

### 10.3 Le fichier d'en-têtes Bitcoin

Les en-têtes ne sont pas une partie du dossier (CT-1 §11.1 en fixe les douze
parties) : ils forment une entrée distincte, désignée sur la ligne de
commande (section 8), schéma `spec/schemas/entetes-bitcoin-v0.schema.json`.

Exemple, valide contre le schéma : l'en-tête du bloc 358391 du réseau
principal, dont les octets 36 à 67 portent le résultat des opérations de
`hello-world.txt.ots` (R2-F30).

<!-- schema: entetes-bitcoin -->
```json
{
  "version": 0,
  "network": "mainnet",
  "start_height": 358391,
  "source": "en-tête du bloc 358391, celui de l'exemple hello-world.txt.ots d'OpenTimestamps",
  "headers": [
    "0x02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6"
  ]
}
```

**EX-10.3** `headers` est une suite contiguë d'en-têtes bruts de 80 octets
dans l'ordre de sérialisation de Bitcoin (R2-F43), de hauteur `start_height`
à `start_height + n − 1` (au plus 200 000 en-têtes, EX-4.13). Un en-tête
n'est jamais remplacé par une valeur affichée par un explorateur ou un appel
RPC (`merkleroot`, `hash`) : ces affichages inversent l'ordre des octets
(R2-F28, R2-F29).

**EX-10.4** Le fichier d'en-têtes n'est **pas** une ancre : quiconque peut le
produire (CT-5 PEUT le joindre au dossier, section 13), et il n'est cru qu'au
travers de O-5, qui le rattache au point de contrôle de l'ancre. Un fichier
illisible ou non conforme à son schéma rend l'entrée inutilisable (N-2,
section 12) ; un fichier conforme qui ne se rattache pas fait échouer O-5.

Notations : `H(i)` est l'en-tête de hauteur `i` ; `dSHA(x)` =
SHA-256(SHA-256(x)) (R2-F44) ; `prev(i)` = octets 4 à 35 de `H(i)` ;
`racine(i)` = octets 36 à 67 ; `nTime(i)`, `nBits(i)` = entiers petit-boutistes
des octets 68 à 71 et 72 à 75 ; `s` et `t` les hauteurs du premier et du
dernier en-tête ; `c` la hauteur du point de contrôle de l'ancre.

### 10.4 Vérifications O-1 à O-7

| Id | Vérification | En anglais | Ancre ou en-têtes nécessaires | Exécutée si |
|---|---|---|---|---|
| O-1 | Format | format | non | partie présente |
| O-2 | Empreinte = `periodHash` | file digest = `periodHash` | non | O-1 réussie, P-1 réussie |
| O-3 | Opérations | operations | non | O-1 réussie |
| O-4 | Attestation Bitcoin contre l'en-tête | Bitcoin attestation against the header | oui | O-3 et O-5 réussies |
| O-5 | Chaîne d'en-têtes rattachée au point de contrôle | header chain connected to the checkpoint | oui | une attestation Bitcoin présente (O-7), fichier d'en-têtes fourni (sinon `partie_absente`, EX-4.5) et ancre `bitcoin` fournie (sinon `ancre_absente`) |
| O-6 | Profondeur | depth | oui | O-4 réussie |
| O-7 | Présence d'une attestation Bitcoin | presence of a Bitcoin attestation | non | O-1 réussie |

**EX-10.5 (O-1, format)** Le fichier suit 10.2 : en-tête magique, version
`01`, opération `08`, 32 octets d'empreinte, arbre conforme à la grammaire,
charges utiles connues consommées exactement, lecture stricte de EX-10.2, fin
de fichier exacte. Une étiquette d'opération inconnue rend le fichier illisible
(R2-F15).

**EX-10.6 (O-2, empreinte)** Les 32 octets d'empreinte du fichier égalent les
32 octets de `periodHash`. O-3 à O-7 s'exécutent même si O-2 échoue : la
preuve est examinée pour elle-même, et le rapport le dit.

**EX-10.7 (O-3, opérations)** Les opérations du profil sont exécutées depuis
l'empreinte du fichier : `f0` rend `m ‖ argument`, `f1` rend
`argument ‖ m`, `08` rend SHA-256(`m`) (R2-F12). Chaque message d'entrée et
chaque résultat a de 1 à 4096 octets (R2-F13) ; sinon O-3 échoue. Une
opération `02`, `03`, `67`, `f2` ou `f3` n'est pas exécutée, ni rien sous
elle : toute attestation située sous elle est `non_execute`
(`hors_perimetre_version`) et signale AV-O-2. O-3 réussit si les opérations
du profil s'exécutent sans défaut ; les opérations hors profil ne changent
pas son statut. Motif du profil `{f0, f1, 08}` : il suffit à la réponse de
calendrier public observée (une seule, du calendrier Alice : `sha256`,
`prepend`, `append`, R2-F76 ; non garanti par une spécification) et aux
opérations qu'ajoute `ots stamp` (`f0` puis `08`, R2-F77) ; l'exemple
officiel `hello-world.txt.ots` emploie `03` et serait hors profil (R2-F25).
Le profil évite aussi aux vérificateurs JavaScript et Go une dépendance à
RIPEMD-160 et au Keccak d'OpenTimestamps ; `reverse` est annoncé comme
susceptible d'être retiré (R2-F14).

**EX-10.8 (O-4, attestation Bitcoin)** Pour chaque attestation Bitcoin de
hauteur `h` dont le chemin est dans le profil, le résultat `r` des opérations
fait exactement 32 octets et égale **octet pour octet, sans inversion**
`racine(h)` (R2-F26, R2-F27 ; contrôlé sur données réelles, bloc 358391 et
`hello-world.txt.ots`, R2-F30). `H(h)` absent du fichier (`h < s` ou
`h > t`) : cette attestation est `non_execute` (`ancre_absente`). Statut de
O-4 : `reussi` si au moins une attestation Bitcoin concorde ; `echoue` si au
moins une a été comparée et qu'aucune ne concorde ; `non_execute` sinon. Une
attestation qui ne concorde pas à côté d'une attestation qui concorde lève
AV-O-1 et ne fait pas échouer O-4 : une réorganisation peut invalider une
attestation ancienne sans invalider la preuve (R2-F36).

**EX-10.9 (O-5, chaîne d'en-têtes)** Toutes les conditions suivantes :

1. `network` du fichier = `network` de l'ancre ;
2. pour tout `i` de `s + 1` à `t` : `prev(i)` = `dSHA(H(i − 1))` (R2-F48) ;
3. `s ≤ c ≤ t`, et l'inverse des 32 octets de `dSHA(H(c))`, écrit en
   hexadécimal, égale `checkpoint.hash` de l'ancre (ordre d'affichage de
   Bitcoin Core, R2-F28) ; si `c < s` ou `c > t`, le fichier ne contient pas
   la hauteur du point de contrôle et O-5 est `non_execute` (`ancre_absente`),
   comme sans ancre `bitcoin` (EX-4.9) : rien dans le dossier ne contredit
   l'ancre, et l'exportateur ne connaît pas le point de contrôle du réviseur ;
   un hachage différent à la hauteur `c` fait échouer O-5 ;
4. pour tout `i` de `c + 1` à `t` : `cible(i)` = `SetCompact(nBits(i))` n'est
   ni négative, ni nulle, ni en débordement, et ne dépasse pas `powLimit` du
   réseau ; l'entier petit-boutiste de 256 bits `dSHA(H(i))` est ≤ `cible(i)`
   (R2-F45, R2-F46) ;
5. difficulté, pour tout `i` de `c + 1` à `t` :
   - `regtest` : `nBits(i)` = `0x207fffff` ;
   - `mainnet` : si `i mod 2016 ≠ 0`, `nBits(i)` = `nBits(i − 1)` ; sinon
     `nBits(i)` = `GetCompact(min(powLimit, SetCompact(nBits(i − 1)) × Δ ÷
     1 209 600))`, où `Δ` = `nTime(i − 1) − nTime(i − 2016)` ramené dans
     `[302 400, 4 838 400]`, la division étant entière et faite après la
     multiplication (R2-F49) ; si `i − 2016 < s`, la règle n'est pas
     applicable et O-5 est `non_execute` (`ancre_absente`) ;
6. pour tout `i` de `c + 1` à `t` tel que `i − 11 ≥ s` : `nTime(i)` est
   strictement supérieur à la médiane de `nTime(i − 11)` … `nTime(i − 1)`
   (sixième valeur des onze, triées) (R2-F38).

Les en-têtes de hauteur `≤ c` ne sont tenus que par la règle 2 : chacun est
désigné par le hachage de son successeur, jusqu'au point de contrôle que
l'ancre déclare. Les en-têtes au-dessus de `c` sont tenus par le travail. La
règle des deux heures de Bitcoin Core dépend de l'horloge du nœud à la
réception et n'est pas vérifiable après coup (R2-F39) : elle n'est pas
contrôlée.

| Réseau | `powLimit` | Source |
|---|---|---|
| `mainnet` | `0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | R2-F51 |
| `regtest` | `0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` ; `nBits` constant `0x207fffff` | R2-F53 |

`SetCompact(x)` : `taille` = `x >> 24`, `mot` = `x & 0x007fffff` ; `mot'` =
`mot >> 8 × (3 − taille)` si `taille ≤ 3`, `mot` sinon ; `N` = `mot'` si
`taille ≤ 3`, `mot << 8 × (taille − 3)` sinon ; négatif si `mot' ≠ 0` et
`x & 0x00800000 ≠ 0` ; débordement si `mot' ≠ 0` et (`taille > 34`, ou
`mot' > 0xff` et `taille > 33`, ou `mot' > 0xffff` et `taille > 32`). `GetCompact(N)` : `taille` = nombre d'octets de `N` ; `compact` = `N
<< 8 × (3 − taille)` si `taille ≤ 3`, `N >> 8 × (taille − 3)` sinon ; si
`compact & 0x00800000 ≠ 0`, `compact >>= 8` et `taille += 1` ; résultat
`compact | (taille << 24)`. Ces deux fonctions, la règle de 5 et la constante
2016 viennent de Bitcoin Core (R2-F45, R2-F49 ; `src/arith_uint256.cpp` et
`src/pow.cpp` du commit `152a55397e451fed9c10041bddf01aa6839847d5`,
https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/pow.cpp,
lus dans la copie du digest R2).

**EX-10.10 (O-6, profondeur)** Pour l'attestation concordante de plus petite
hauteur `h` (celle qui a le plus de blocs au-dessus d'elle), `k` = `t − h + 1`
≥ `min_confirmations` de l'ancre. Sinon O-6 est `non_execute`
(`ancre_absente`) : la chaîne fournie ne porte pas assez de travail au-dessus
du bloc pour ce que le réviseur exige. Aucune valeur normative de `k`
n'existe dans les sources : 6 est la valeur par défaut du serveur de calendrier
(R2-F73). Le livre blanc compte z blocs liés après le bloc attesté (§11), soit
z = k − 1 : pour un attaquant à 10 % de la puissance, k = 6 (z = 5) donne une
probabilité de rattrapage de 0,0009137, et k = 7 (z = 6) de 0,0002428
(R2-F57, https://bitcoin.org/bitcoin.pdf §11).

**EX-10.11 (O-7, attestation Bitcoin présente)** O-7 réussit si l'arbre porte
au moins une attestation Bitcoin, et est `non_execute` (`partie_absente`)
sinon : une preuve qui n'a que des attestations en attente n'a pas encore été
complétée par `ots upgrade` (R2-F75), opération qui exige le réseau et que le
vérificateur ne fait jamais. Les attestations en attente et inconnues lèvent
AV-O-2.

### 10.5 Statut du contrôle 5 et attestation retenue

**EX-10.12** Partie `preuve_ots` absente : `non_execute`, avec la raison de
EX-4.3. Sinon : `echoue` si O-1, O-2, O-3, O-4 ou O-5 échoue ; sinon `reussi`
si O-2, O-4, O-6 et O-7 réussissent ; sinon `non_execute`, avec la raison que
choisit EX-6.5 (une attestation hors profil donne `hors_perimetre_version`,
une preuve en attente ou un fichier d'en-têtes non fourni `partie_absente`,
une ancre `bitcoin` absente, un fichier d'en-têtes sans la hauteur du point de
contrôle ou une profondeur insuffisante `ancre_absente`).
L'attestation retenue est celle de O-6, la concordante de plus petite
hauteur, comme le fait le client officiel (R2-F31).

### 10.6 Ce que dit le temps du bloc

Le seul fait démontré est que `periodHash` existait avant la création du bloc
`h` (R2-F37, R2-F58). `nTime(h)` est inscrit par le mineur ; le consensus
impose seulement qu'il dépasse la médiane des onze blocs précédents
(R2-F38), les heures des blocs ne sont pas ordonnées (R2-F40), et l'estimation
« deux ou trois heures, presque certainement un jour » est celle de Peter
Todd, auteur d'OpenTimestamps (annonce du 2016-09-15,
https://petertodd.org/2016/opentimestamps-announcement), non une règle de
Bitcoin (R2-F37 et point non vérifié 5 du digest R2).

**EX-10.13** Le vérificateur annonce : `block_time` = `nTime(h)` en UTC,
qualifié d'« heure inscrite par le mineur, précision non garantie par le
protocole » ; et, si `t ≥ h + 11`, `median_bound` = médiane de `nTime(h + 1)`
… `nTime(h + 11)`, qualifiée de « borne sous hypothèse ». Hypothèse, déduite
par cette spécification et non tirée d'une source : si au moins six des onze
blocs suivants portent l'heure honnête de leur création, à la dérive
d'horloge près, la création du bloc `h` précède `median_bound` augmentée de
cette dérive (au moins une heure honnête est inférieure ou égale à la
médiane, et chaque bloc suivant a été créé après `h`). Le client officiel
n'annonce que le jour, en heure locale (R2-F33) ; le vérificateur écrit des
instants UTC.

### 10.7 Avertissements et valeurs rapportées

| Avertissement | Condition |
|---|---|
| AV-O-1 | Attestation Bitcoin qui ne concorde pas, à côté d'une attestation qui concorde. |
| AV-O-2 | Attestation en attente, inconnue, ou hors profil, non exploitée. |
| AV-O-3 | O-5 exécutée sur le réseau `regtest` : un réseau d'essai, sans valeur probante hors des tests (R2-F22 : l'attestation ne porte pas le réseau, c'est l'ancre qui le fixe). |

**EX-10.14** Pour le contrôle 5, le rapport porte au moins : `file_digest`,
`network`, `checkpoint` (`{height, hash}`), `attestations` (liste
`{kind: "bitcoin" | "en_attente" | "inconnue", height | uri | tag, status}`),
`retained_height`, `block_hash` (ordre d'affichage), `block_time`,
`median_bound` (ou `null`), `confirmations`, `cumulative_work` (chaîne
décimale : somme, sur les en-têtes de hauteur `max(h, c + 1)` à `t`, de
`⌊2²⁵⁶ ÷ (cible + 1)⌋`, R2-F47).

### 10.8 Énoncé produit

**EX-10.15** Quand le contrôle 5 réussit, il fournit à l'énoncé de la section
6 :

- français : « le manifeste d'empreinte `<periodHash>` existait avant la
  création du bloc Bitcoin `<retained_height>` (`<block_hash>`, réseau
  `<network>`), sous `<confirmations>` blocs dont le travail se rattache au
  point de contrôle `<checkpoint.height>` du réviseur ; heure inscrite par le
  mineur : `<block_time>` UTC, précision non garantie par le protocole »,
  suivi, si `median_bound` existe, de « ; borne sous hypothèse :
  `<median_bound>` UTC » ;
- anglais : “the manifest with digest `<periodHash>` existed before Bitcoin
  block `<retained_height>` (`<block_hash>`, `<network>` network) was
  created, under `<confirmations>` blocks whose work connects to the
  reviewer's checkpoint `<checkpoint.height>`; time written by the miner:
  `<block_time>` UTC, accuracy not guaranteed by the protocol”, suivi de “;
  bound under assumption: `<median_bound>` UTC”.

Sur `regtest`, la proposition se termine par une espace suivie de « (réseau
d'essai, sans valeur probante) » (“(test network, no evidential value)”).

Note non normative. Le passage « dont le travail se rattache au point de
contrôle » se lit comme le dit 7.2 (contrôle 5). Le travail n'est recalculé
qu'au-dessus du point de contrôle (EX-10.9, `cumulative_work` d'EX-10.14).
Il peut ne l'être pour aucun bloc : quand t = c, `cumulative_work` vaut 0.
Le texte de la proposition ne change pas.

## 11. Contrôle 8 : registre et certificat de commit

### 11.1 Ce que le contrôle établit, et pourquoi tout se recalcule

Le contrôle 8 établit qu'un quorum d'un jeu de validateurs **que le réviseur
déclare** a signé des blocs du registre dont les reçus portent la clôture et
l'ancre de la période. Rien n'y est lu comme un avis du nœud :

- le hachage d'un bloc de noorcore en mode BFT n'est pas `keccak256(RLP(en-tête))`
  mais `BFTBlockHash`, un keccak256 sur une préimage fixe de 212 octets
  (R3 F1, F2 ; `core/node/blockexec.go:135-179` de noorchain-core au commit
  `618fcef`) ; dix variantes d'en-tête go-ethereum, de pré-London à Prague, ne
  redonnent pas le hachage servi, `BFTBlockHash` le redonne (R3 F4) ;
- l'égalité du champ `blockHash` d'un reçu avec celui du certificat ne lie pas
  le reçu au bloc : un reçu falsifié garde le `blockHash` certifié, seul le
  recalcul de `receiptsRoot` le refuse (R3 F21, F32) ;
- `canonical.matchesCertificate` et `validatorSetMatchesCertificate` sont des
  affirmations du nœud, sans vérification cryptographique (R3 F20) ;
- les valeurs d'état (`getPeriod`, `lookup`, `recorderByPubKey`, appartenance
  au `CuratorSet`, non-révocation) sont servies sans preuve, et ni
  `eth_getProof` ni `debug_getRawReceipts` n'existent (R3 F29, F30, F41) :
  elles ne sont pas des preuves et ne figurent pas dans un dossier v0.

**EX-11.1** Le vérificateur recalcule le hachage de chaque bloc, la racine des
reçus de chaque bloc, le hachage du jeu de validateurs et chaque condensé
signé ; il ignore tout champ de `certificat-commit.json` autre que ceux que
11.2.2 nomme, et toute valeur d'état.

### 11.2 Les trois parties

L'inscription de la clé, l'ancre et la clôture tombent dans des blocs
distincts, chacun avec son certificat (R3 F39) : `registre.json` porte donc
une **entrée par transaction prouvée**, et `certificat-commit.json` un
certificat par bloc. Les noms de fichiers et l'ordre des douze parties de
CT-1 §11.1 ne changent pas.

#### 11.2.1 `registre.json` (schéma `registre-v0.schema.json`)

| Clé | Contenu |
|---|---|
| `version` | `0` |
| `source` | texte libre (1 à 512 caractères) : nœud interrogé, date de la capture ; déclaratif |
| `entries` | de 2 à 16 entrées ; exactement une de rôle `cloture`, exactement une de rôle `ancre`, au plus 8 de rôle `inscription` |
| `entries[].role` | `cloture` (`PeriodRegistry.submitPeriod`), `ancre` (`AttestationRegistry.anchor`), `inscription` (`RecorderRegistry.registerRecorder`) |
| `entries[].block` | les dix champs de l'en-tête que la préimage de 11.3.1 engage, tels que `eth_getBlockByNumber(h, false)` les rend : `number`, `hash`, `parentHash`, `timestamp`, `stateRoot`, `transactionsRoot`, `receiptsRoot`, `gasUsed`, `gasLimit`, `baseFeePerGas` ; aucun autre (`logsBloom`, `miner`, `nonce`, `sha3Uncles`, `mixHash`, `extraData`, `size`, `difficulty` ne sont pas engagés, R3 F5) |
| `entries[].receipts` | **tous** les reçus du bloc, dans l'ordre des transactions : `type`, `status`, `cumulativeGasUsed`, `logs[]` (`address`, `topics`, `data`) ; aucun autre champ |
| `entries[].transaction_index` | indice, dans `receipts`, du reçu de la transaction prouvée |
| `entries[].log_index` | indice, dans les `logs` de ce reçu, du journal prouvé |
| `entries[].transaction_hash` | hachage déclaré de la transaction ; rapporté, non vérifié en version 0 (11.8) |

Quantités en hexadécimal minuscule sans zéro de tête (`0x0`, `0x3e40`),
hachages et adresses en hexadécimal minuscule de longueur fixe, comme CT-1 §3
(les adresses servies en casse mixte EIP-55 sont mises en minuscules par
l'exportateur).

**EX-11.2** Les reçus sont tous ceux du bloc parce que la racine se recalcule
sur tous (11.3.2). Ce n'est pas une divulgation supplémentaire : le
certificat porte déjà, dans le corps signé de la proposition, les
transactions brutes du bloc entier, qui ne se caviardent pas sans casser la
signature (R3 F18, F47). La variante « reçu cible et preuve Merkle-Patricia »
(R3 F27) est réservée à une version ultérieure (section 17).

Exemple : la capture du 2026-10-22 décrite par le digest R3 (bloc 15936,
ancre ; bloc 15940, clôture), valide contre le schéma ; ses racines et
hachages se recalculent.

<!-- schema: registre -->
```json
{
  "version": 0,
  "source": "réseau de développement noortrace-2124-dev, nœud v1, parcours npm run e2e:noorcore du 2026-10-22 (organisation e2e-1792701883432)",
  "entries": [
    {
      "role": "ancre",
      "block": {
        "number": "0x3e40",
        "hash": "0xc1a517ccab7e5eafa00a60cd883f534045eb3b6c74508b6567ef4946ee083ab0",
        "parentHash": "0x2ba23e0614563b438bfa9df1491c41f6bebfcaeb68acbc58c3207d99c986fded",
        "timestamp": "0x6ada75c7",
        "stateRoot": "0xb70484fbc4c8af4b825885d4334fb33ec7a5059e9e940bdd3eb50755324589d6",
        "transactionsRoot": "0x56310d8af51559551fa5f053674e21a9008a7038fded075670c957c380c01d30",
        "receiptsRoot": "0xf675d350c067d714bc3a4944fccd9ce99012a141ddba005c6ce58de91f9bf7aa",
        "gasUsed": "0x17ad1",
        "gasLimit": "0x1c9c380",
        "baseFeePerGas": "0x1"
      },
      "receipts": [
        { "type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x17ad1", "logs": [
          { "address": "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8",
            "topics": [
              "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e",
              "0xe50f265649a083eb9e26ebe31da52b3dc339bc3ff0b8482f4ac98a82cadb03fd",
              "0x000000000000000000000000f96f92a3a4ab61b39ae5f61c5d86e9fb3957a7cd"
            ],
            "data": "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee" }
        ] }
      ],
      "transaction_index": 0,
      "log_index": 0,
      "transaction_hash": "0x115c44660ed44074dbe375cd3ffce21570fce670949070c0c37b8ae3264d6db1"
    },
    {
      "role": "cloture",
      "block": {
        "number": "0x3e44",
        "hash": "0xfe3a9ac962db7cd4055eae754078a8c2d05c34c4328b1f4c5d6992623e840c72",
        "parentHash": "0x6787c2dc452f906d40e8886f0fa27e53f7320b168919dd121a418aeb064704c3",
        "timestamp": "0x6ada75cb",
        "stateRoot": "0x64175e8746ff46e32b3f93a673a791273c65b507bd83fb0f96305667f78cc67c",
        "transactionsRoot": "0x594bf831ae50f5031ef7c3049d981219cd9f0fb4abca939c659aeac4930741a7",
        "receiptsRoot": "0x91f22eca4fc679aca4f83a2aa6859d4eadb6efb5fa25934a33c1689ea14bb575",
        "gasUsed": "0x4cb90",
        "gasLimit": "0x1c9c380",
        "baseFeePerGas": "0x1"
      },
      "receipts": [
        { "type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x4cb90", "logs": [
          { "address": "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
            "topics": [
              "0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba",
              "0x0000000000000000000000000000000000000000000000000000000000000004",
              "0x8522299c1f8b3788afa7e43f02a2166e5142d71c514358f6a07903fdcfb2852b",
              "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            ],
            "data": "0xfda1c202fd09678d669aa2b571d83ccccefaa26a712308aa81deb5390be23b8c0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b35bd2fa3a4b0cc97c4d1a4b7b617a1e39c4e77c0a68c397e4ee0989cf45b2a22000000000000000000000000000000000000000000000000000000006ada6b40000000000000000000000000000000000000000000000000000000006ada79500000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000006ada75cb00000000000000000000000000000000000000000000000000000000000000216532653a2f2f6532652d313739323730313838333433322f706572696f64652f3100000000000000000000000000000000000000000000000000000000000000" }
        ] }
      ],
      "transaction_index": 0,
      "log_index": 0,
      "transaction_hash": "0xb086fc581958ef04a93c2f3a5ee0fdb57b486afd246254dd1b2848ef93b9b00b"
    }
  ]
}
```

#### 11.2.2 `certificat-commit.json` (schéma `registre-v0.schema.json#/$defs/certificat_commit`)

`{ "version": 0, "certificates": [ … ] }`, un certificat par hauteur de bloc
nommée par `registre.json`, chacun étant le résultat (`result`) de
`noor_getCommitCertificate` tel que le nœud le rend (forme décrite dans
`chain/README.md` et `scripts/verify/README.md` ; exemple complet :
`test/fixtures/certificat-commit/certificat-8316.json`).

**EX-11.3** Le vérificateur ne lit, dans chaque certificat, que `height`,
`round`, `chainId`, `valsetHash`, `blockHash`, `proposal.line` et
`precommits[].line` ; les lignes sont relues octet par octet, jamais les
champs décodés à côté (`validatorId`, `bodyHash`, `sig`), ni `validatorSet`,
`validatorSetHash`, `canonical`, `quorum`, `retention`, `signing` (R3 F20,
F22 ; `scripts/verify/README.md`, « Ce qu'est un certificat de commit »).
La ligne de proposition est exigée en version 0 ; un certificat réduit aux
precommits n'est pas admis (sa sûreté n'est pas établie, R3 NV1).

#### 11.2.3 `validateurs.json` (schéma `validateurs-v0.schema.json`)

`{ "version": 0, "sets": [ { "from_height", "to_height", "validators": [ {
"id", "pubKeyHex" } ], "source" } ] }` : le ou les jeux que l'exportateur
**déclare**, dans la forme du fichier `validators.json` du réseau
(`chain/README.md`), avec leur intervalle de hauteurs (`to_height` nul : sans
borne haute) et leur provenance. La partie est déclarative : le quorum se
calcule toujours sur le jeu de l'ancre (R-2), et la partie ne sert qu'au
contrôle de cohérence R-3 et à guider le réviseur qui construit son ancre
(section 12). Elle PEUT être absente avec une raison.

### 11.3 Recalculs

#### 11.3.1 Hachage du bloc

**EX-11.4** `BFTBlockHash` = keccak256 (Keccak d'origine, celui de l'EVM) de
la préimage de 212 octets :

| Octets | Champ | Codage |
|---|---|---|
| 20 | `"noor/v1/bftblockhash"` | ASCII, `6e6f6f722f76312f626674626c6f636b68617368` |
| 32 | `parentHash` | brut |
| 8 | `number` | entier non signé grand-boutiste |
| 8 | `timestamp` | idem |
| 32 | `stateRoot` | brut |
| 32 | `transactionsRoot` | brut |
| 32 | `receiptsRoot` | brut |
| 8 | `gasUsed` | entier non signé grand-boutiste |
| 8 | `gasLimit` | idem |
| 32 | `baseFeePerGas` | entier grand-boutiste complété à gauche par des zéros |

Source : R3 F1 (préimage) et F4 (expérience). Les champs viennent de l'en-tête
de `registre.json`, jamais du corps signé de la proposition, dont le
validateur ne compare pas individuellement `gasLimit`, `baseFeeHex` ni un
`parentHash` nul (R3 F7, conséquence 2).

Exemple, bloc 8316 de la fixture publique
`test/fixtures/certificat-commit/bloc-8316.json` (recalculé pour cette
spécification ; même valeur que R3 F4) :

```text
préimage = 6e6f6f722f76312f626674626c6f636b68617368
           293cde1df216315a74cfa45851f246fd1e32f6d92734c26ac567be95968f1bc2
           000000000000207c 000000006ad8b09f
           6d3c48fd05042b6c6c65bec56affb2db5d7b1571a4f4df22b81f8410246de64a
           2b733fd11b9a29ec7ee2135b50c9e4b8e878088c95d613fbe287f9a22d91612b
           9a980c5c887bb493cffb54eb12dbbabfcaa6f27bedbbadd166797b91b4c75220
           000000000006a8d2 0000000001c9c380
           0000000000000000000000000000000000000000000000000000000000000001
BFTBlockHash = 0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c
             = hash du bloc = blockHash de certificat-8316.json
```

#### 11.3.2 Racine des reçus

**EX-11.5** `receiptsRoot` = racine du trie Merkle-Patricia d'Ethereum dont
les clés sont `RLP(i)` et les valeurs l'encodage de consensus du reçu `i`,
pour `i` de 0 au nombre de reçus moins un ; c'est `types.DeriveSha` de
go-ethereum v1.17.0, version que noorchain-core épingle (R3 F23, F24 ;
EIP-2718, statut Final, https://eips.ethereum.org/EIPS/eip-2718, R3 F25).
Règles exactes :

1. **RLP.** Chaîne d'octets `b` : `b` lui-même si `|b| = 1` et `b[0] < 0x80` ;
   `0x80 + |b|` ‖ `b` si `|b| ≤ 55` ; sinon `0xb7 + |L|` ‖ `L` ‖ `b`, `L` étant
   la longueur en grand-boutiste minimal. Liste de charge `P` (concaténation
   des encodages des éléments) : `0xc0 + |P|` ‖ `P` si `|P| ≤ 55`, sinon
   `0xf7 + |L|` ‖ `L` ‖ `P`. Un entier est la chaîne de ses octets
   grand-boutistes minimaux (zéro : chaîne vide).
2. **Bloom d'un reçu** (256 octets, nuls au départ). Pour chaque journal, pour
   `d` pris dans l'adresse (20 octets) puis chaque sujet (32 octets) :
   `h` = keccak256(`d`) ; pour `k` dans 0, 2, 4 : `n` = ((`h[k]` × 256) +
   `h[k+1]`) & 0x7ff ; l'octet d'indice `255 − (n >> 3)` reçoit le bit
   `1 << (n & 7)` (go-ethereum v1.17.0, `core/types/bloom9.go:143-158`, `bloomValues`). Le
   bloom n'est pas servi dans les reçus de noorcore et se recalcule toujours
   (R3 F28).
3. **Encodage d'un reçu.** `C` = RLP([`statut`, `cumulativeGasUsed`, `bloom`,
   journaux]) où `statut` est la chaîne vide pour `status` = `0x0` et l'octet
   `01` pour `0x1` ; chaque journal est RLP([adresse (20 octets), [sujets
   (32 octets chacun)], données]). Reçu de `type` 0 : `C` ; de `type` 1 à 4 :
   l'octet de type ‖ `C` (go-ethereum v1.17.0, `core/types/receipt.go`,
   `receiptRLP`, `statusEncoding`, `EncodeIndex`, R3 F24). Un reçu de type 2
   encodé comme un reçu ancien donne une autre racine (R3 F26).
4. **Trie.** Clés en quartets. Pour un ensemble de couples (clé, valeur) :
   un seul couple donne une feuille [HP(clé, feuille), valeur] ; un préfixe
   commun non vide de longueur `p` donne une extension [HP(préfixe,
   extension), réf(nœud des suffixes)] ; sinon une branche de 17 éléments
   dont l'élément `d` (0 à 15) est réf(nœud des couples dont la clé commence
   par `d`, privée de ce quartet) ou la chaîne vide, et l'élément 16 la
   valeur de clé vide ou la chaîne vide. HP (hex-prefix) : drapeau `f` = 2
   pour une feuille, 0 pour une extension ; longueur impaire : premier octet
   `((f + 1) << 4) | q₀` puis les quartets suivants par paires ; paire :
   octet `f << 4` puis les paires. réf(`n`) = `n` si |RLP(`n`)| < 32, sinon
   keccak256(RLP(`n`)). Racine = keccak256(RLP(nœud de tous les couples)) ;
   sans reçu, keccak256(`80`).

Ces règles, écrites pour cette spécification, redonnent la racine servie des
blocs 15932, 15936, 15940 (un reçu de type 2) et 16324 (trois reçus de types
2, 2 et 0) de la capture R3 ; les vecteurs de l'annexe A les confrontent à
go-ethereum.

#### 11.3.3 Certificat de commit

**EX-11.6** Lecture des lignes : celle du vérificateur
`scripts/verify/README.md` (« Ce que le vérificateur accepte : ce que le
décodeur du nœud accepte »), ni plus ni moins ; une ligne acceptée sous une
forme non canonique lève AV-R-2.

**EX-11.7** Condensé signé par chaque validateur (R3 F11 ;
`core/consensus/signing.go` de noorchain-core) :

```text
sha256( "noor/v1/bft-sign|" ‖ LP("noor/v1/bft") ‖ LP(chainId) ‖ LP(type) ‖ LP(validatorId)
        ‖ valsetHash (32) ‖ u64be(height) ‖ u64be(round) ‖ blockHash (32) ‖ bodyHash (32) )
LP(x)    = longueur de x sur 4 octets grand-boutistes ‖ x
bodyHash = sha256(octets d'origine du corps de la ligne)
type     = "CONS_PROPOSAL" ou "CONS_PRECOMMIT"
```

Signature secp256k1 de 65 octets `R ‖ S ‖ V`, `S` bas, `V` dans {0, 1} ; la
clé recouvrée, sous forme non compressée, égale la clé du validateur nommé,
ramenée à la même forme (R3 F12).

**EX-11.8** Hachage d'un jeu (R3 F14) : sha256(`"noor/v1/valsethash|"` ‖ pour
chaque identifiant pris dans l'ordre croissant de ses octets : identifiant ‖
`00` ‖ octets de la clé publique **tels que déclarés** ‖ `00`). Deux
déclarations de la même clé sous deux formes (65 octets non compressée, 33
octets compressée) donnent deux hachages : le jeu de l'ancre reprend les clés
telles que le réseau les configure. Quorum de `N` validateurs :
`⌊(N + f) / 2⌋ + 1`, `f = ⌊(N − 1) / 3⌋`, soit 3 pour 4 (R3 F15).

#### 11.3.4 Journaux d'événements

**EX-11.9** Le journal prouvé est `receipts[transaction_index].logs[log_index]`
de son entrée ; sa forme selon le rôle :

| Rôle | Contrat de l'ancre | `topics[0]` (keccak256 de la signature, R3 F33-F35) | Autres sujets | `data` |
|---|---|---|---|---|
| `cloture` | `period_registry` | `0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba` | `[1]` id, `[2]` `periodHash`, `[3]` relayeur | mots de 32 octets : `w0` orgId, `w1` journalId, `w2` root, `w3` periodStart, `w4` periodEnd, `w5` firstSeq, `w6` lastSeq, `w7` version, `w8` = `0x140` (position de `uri`), `w9` publishedAt ; puis la longueur de `uri` et ses octets complétés à un multiple de 32 |
| `ancre` | `attestation_registry` | `0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e` | `[1]` empreinte, `[2]` émetteur | 32 octets : `docType` |
| `inscription` | `recorder_registry` | `0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec` | `[1]` orgId, `[2]` chainKey, `[3]` journalId | 64 octets : clé Ed25519, relayeur |

Signatures :
`PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)`,
`Anchored(bytes32,address,bytes32)`,
`RecorderRegistered(bytes32,address,bytes32,bytes32,address)`
(`contracts/PeriodRegistry.sol`, `AttestationRegistry.sol`,
`RecorderRegistry.sol` ; disposition des données observée sur la capture R3,
F38). Un entier (`uint64`, `uint32`) ou une adresse occupe un mot dont les
octets de tête sont nuls.

### 11.4 Vérifications R-1 à R-10

| Id | Vérification | En anglais | Ancre nécessaire | Portée |
|---|---|---|---|---|
| R-1 | Parties conformes et appariées | parts well-formed and matched | non | parties |
| R-2 | Jeu de validateurs de l'ancre | validator set of the anchor | oui | chaque certificat |
| R-3 | Cohérence de `validateurs.json` | consistency of `validateurs.json` | non | chaque certificat |
| R-4 | Identifiant de chaîne | chain identifier | oui | chaque certificat |
| R-5 | Signatures et quorum | signatures and quorum | oui | chaque certificat |
| R-6 | Hachage du bloc | block hash | non | chaque entrée |
| R-7 | Racine des reçus | receipts root | non | chaque entrée |
| R-8 | Contrat émetteur | emitting contract | oui | chaque entrée |
| R-9 | Événement et valeurs de la période | event and period values | non | entrées `cloture` et `ancre` |
| R-10 | Inscriptions | registrations | non | entrées `inscription` |

Le statut d'une vérification qui porte sur plusieurs certificats ou entrées est
`echoue` si l'une échoue, sinon `non_execute` si l'une n'est pas exécutée, sinon
`reussi`.

**EX-11.10 (R-1, parties)** `registre.json` et `certificat-commit.json` sont
présents, exploitables (objets JSON, limites de EX-4.13, bornes de 15.1) et conformes à
leurs schémas ; chaque hauteur `block.number` d'une entrée a exactement un
certificat de même `height`, et chaque certificat sert au moins une entrée ;
`transaction_index` désigne un reçu et `log_index` un journal de ce reçu.
Sinon R-1 échoue et R-2 à R-10 sont `non_execute`, raison
`prerequis_en_echec`.

**EX-11.11 (R-2, jeu de l'ancre)** Pour chaque certificat de hauteur `h`,
l'ancre `registry` déclare un jeu dont l'intervalle `[from_height, to_height]`
contient `h`, et le hachage de ce jeu (EX-11.8) égale `valsetHash` du
certificat. Pas d'ancre `registry`, ou pas de jeu pour `h` : `non_execute`
(`ancre_absente`). Hachage différent : `echoue` ; c'est le cas d'un certificat
signé par un jeu substitué, même cohérent avec `validateurs.json`.

**EX-11.12 (R-3, `validateurs.json`)** `validateurs.json` est exploitable et
conforme à son schéma, et, pour chaque certificat de hauteur `h`, déclare un
jeu dont l'intervalle contient `h` et dont le hachage égale `valsetHash`.
Partie absente : `non_execute`, avec la raison de EX-4.3 (`hors_perimetre_version`
si la raison déclarée est exactement « hors périmètre CT-1 », `partie_absente`
sinon), sans effet sur le statut du contrôle. Un dossier qui déclare un autre
jeu que celui qui a signé échoue.

**EX-11.13 (R-4, chaîne)** Pour chaque certificat, `chainId` égale, octet pour
octet, `registry.chain_id` de l'ancre. Le `chainId` est lié à chaque signature
(EX-11.7), mais un même jeu de validateurs réutilisé sur un autre réseau y
signe des certificats tout aussi valides (`scripts/verify/README.md`, « Ce
que le vérificateur ne prouve pas ») : seule cette comparaison écarte un
certificat d'une autre chaîne.

**EX-11.14 (R-5, signatures et quorum)** Exécutée si R-2 a réussi pour ce
certificat. La ligne de proposition est une enveloppe `CONS_PROPOSAL` valide
et chaque ligne de precommit une enveloppe `CONS_PRECOMMIT` valide :
domaine `noor/v1/bft`, `chainId`, `valsetHash`, hauteur, tour et
`blockHash` égaux à ceux du certificat, `bodyHash` égal au sha256 des octets
d'origine du corps, corps cohérent (hauteur, tour, bloc ; `proposer` ou
`Voter` égal au signataire quand il est renseigné ; vote de type 2 pour un
precommit), signature selon EX-11.7 sous la clé, dans le jeu de l'ancre, du
validateur nommé (R3 F13). Les signataires des precommits sont distincts et
au moins aussi nombreux que le quorum du jeu de l'ancre (R3 F15, F16). Une
seule ligne invalide fait échouer R-5, même si les autres suffisent
(`scripts/verify/README.md`).

**EX-11.15 (R-6, hachage du bloc)** Pour chaque entrée : `BFTBlockHash` des
champs de `block` (EX-11.4) égale `blockHash` du certificat de même hauteur
et égale `block.hash` ; `block.number` égale `height` du certificat.

**EX-11.16 (R-7, racine des reçus)** Pour chaque entrée : la racine recalculée
sur `receipts` (EX-11.5) égale `block.receiptsRoot`.

**EX-11.17 (R-8, contrat émetteur)** Exécutée pour une entrée si R-6 et R-7 ont
réussi pour elle. L'adresse du journal prouvé égale l'adresse que l'ancre
déclare pour le rôle (`period_registry`, `attestation_registry`,
`recorder_registry`). L'adresse du journal est engagée par l'encodage du reçu
(EX-11.5, règle 3) et suffit à dire quel contrat a émis l'événement (R3,
conséquence 6). Pas d'ancre `registry` : `non_execute` (`ancre_absente`).

**EX-11.18 (R-9, événement et valeurs de la période)** Exécutée pour une
entrée `cloture` ou `ancre` si R-6 et R-7 ont réussi pour elle et si P-1 a
réussi. Le journal a le nombre de sujets (4 pour `cloture`, 3 pour `ancre`),
le `topics[0]` et la disposition de `data` de EX-11.9, octets de remplissage
nuls, et :

- `cloture` : `topics[2]` = `periodHash` recalculé (CT-1 §10.2) ; `w0` =
  `org_id`, `w1` = `journal_id`, `w2` = `root`, `w3` = `period_start`, `w4` =
  `period_end`, `w5` = `first_seq`, `w6` = `last_seq`, `w7` = `version`
  (0), tous lus dans `manifeste.json` ; `w9` = `block.timestamp` de l'entrée
  (le contrat y écrit l'horodatage du bloc, R3 F36, F38) ;
- `ancre` : `topics[1]` = keccak256(`org_id` ‖ `journal_id` ‖ `periodHash`),
  préimage de 96 octets (CT-1 §10.4) ; `data` =
  keccak256(UTF-8(`"noortrace/periode/v0"`)) =
  `0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee`
  (`DOC_TYPE_PERIODE` de `scripts/lib/noortrace.mjs`, R3 F38).

`publishedAt` ne prouve pas l'heure de la clôture : c'est l'horloge du
proposant, bornée par les validateurs à 15 s dans leur futur et non
antérieure au parent (R3 F8), donc une heure déclarée.

**EX-11.19 (R-10, inscriptions)** Exécutée pour chaque entrée `inscription` si
R-6 et R-7 ont réussi pour elle, si P-1 a réussi et si `cles.json` est
conforme à son schéma avec des `key_id` et des `public_key` uniques (première
partie de E-8). Le journal a la forme de EX-11.9 (4 sujets, 64 octets de
données) ; `topics[1]` = `org_id` et `topics[3]` = `journal_id` du
manifeste ; la clé Ed25519 (`data`, premier mot) est la `public_key` d'une clé
de `cles.json` (CT-1 §11.2). Si l'entrée `ancre` a passé R-6 et R-7 et que
des entrées inscrivent la clé de `manifeste.recorder_key_id`, au moins l'une
d'elles a pour clé de chaîne (`topics[2]`, 20 derniers octets) l'émetteur de
l'ancre (`topics[2]` de son journal) : la clé de chaîne qui a signé l'ancre est
celle sous laquelle la clé du manifeste est inscrite (CT-2 EX-11.19). Les
autres inscriptions de cette clé, sous une autre clé de chaîne, ne font pas
échouer R-10 et lèvent AV-R-3 : `RecorderRegistry.registerRecorder` permet de
réinscrire la même clé Ed25519 sous une nouvelle clé de chaîne une fois
l'ancienne révoquée, et le dossier peut joindre l'ancienne inscription.
Aucune inscription de la clé du manifeste sous l'émetteur de l'ancre, alors
qu'il en existe sous d'autres clés de chaîne : R-10 échoue. Aucune entrée
`inscription` : `non_execute` (`partie_absente`), sans effet sur le statut du
contrôle. Aucune inscription de la clé du manifeste : AV-R-1.

### 11.5 Statut du contrôle 8

**EX-11.20** `registre` ou `certificat_commit` absent : contrôle 8
`non_execute`, avec la raison de EX-4.3. Sinon : `echoue` si l'une de R-1 à
R-10, ou N-4 (EX-12.5), échoue ; sinon `reussi` si R-1, R-2 et R-4 à R-9
réussissent ; sinon `non_execute`, avec la raison que choisit EX-6.5 parmi
celles de R-1, R-2, R-4 à R-9. R-3, R-10 et N-4 non exécutées n'empêchent pas
la réussite.

### 11.6 Avertissements et valeurs rapportées

| Avertissement | Condition |
|---|---|
| AV-R-1 | Aucune inscription de la clé du manifeste : l'émetteur de l'ancre n'est relié à aucune clé d'enregistreur. |
| AV-R-2 | Ligne de certificat acceptée sous une forme non canonique (EX-11.6). |
| AV-R-3 | Inscription de la clé du manifeste sous une autre clé de chaîne que l'émetteur de l'ancre, à côté d'une inscription sous l'émetteur (EX-11.19). |

**EX-11.21** Pour le contrôle 8, le rapport porte au moins : `chain_id`,
`entries` (liste `{role, block_number, block_hash, block_time (RFC 3339
UTC de block.timestamp), transaction_index, transaction_hash_declared,
emitter, event}` où `event` donne les valeurs décodées de EX-11.9),
`certificates` (liste `{height, valset_hash, set_source (source du jeu de
l'ancre), set_size, quorum, signers (identifiants)}`).

### 11.7 Énoncé produit

**EX-11.22** Quand le contrôle 8 réussit, il fournit à l'énoncé de la section
6 :

- français : « sur le registre `<chain_id>`, la clôture de cette période
  (organisation `<org_id>`, journal `<journal_id>`) figure au bloc
  `<h_cloture>` (heure déclarée par le bloc : `<t_cloture>` UTC), émise par le
  contrat `PeriodRegistry` `<adresse>`, et son ancre `<empreinte>` au bloc
  `<h_ancre>` (heure déclarée `<t_ancre>` UTC), émise par `AttestationRegistry`
  `<adresse>` pour l'émetteur `<émetteur>` », suivi, si R-10 a réussi pour la
  clé du manifeste, de « , clé de chaîne inscrite au bloc `<h_inscription>`
  pour la clé d'enregistreur `<recorder_key_id>` », et, si N-4 a réussi, de
  « , que le réviseur tient pour la clé de chaîne de `<recorder_key_id>` »,
  puis de `␣;␣` et de la proposition de signature ci-dessous ;
- anglais : “on registry `<chain_id>`, the closing of this period
  (organisation `<org_id>`, journal `<journal_id>`) is in block
  `<h_cloture>` (time declared by the block: `<t_cloture>` UTC), emitted by
  contract `PeriodRegistry` `<address>`, and its anchor `<fingerprint>` in
  block `<h_ancre>` (declared time `<t_ancre>` UTC), emitted by
  `AttestationRegistry` `<address>` for issuer `<issuer>`”, “, chain key
  registered in block `<h_inscription>` for recorder key
  `<recorder_key_id>`”, “, which the reviewer holds as the chain key of
  `<recorder_key_id>`”, puis `;␣` et la proposition de signature
  ci-dessous.

Proposition de signature. Les certificats de `certificat-commit.json` sont
groupés par jeu de l'ancre que R-2 a retenu pour leur hauteur ; les groupes
sont pris dans l'ordre de leur plus petite hauteur. Pour chaque groupe,
`<n>` est le plus petit nombre de signataires distincts des precommits parmi
ses certificats, tous vérifiés par R-5 (chaque bloc du groupe en compte au
moins autant), `<N>` la taille du jeu, `<valset_hash>` son hachage (EX-11.8)
et `<set_source>` sa `source`. Avec un seul groupe :

- français : « chacun de ces blocs est signé par `<n>` des `<N>` validateurs
  du jeu `<valset_hash>` que le réviseur déclare (`<set_source>`) » ;
- anglais : “each of these blocks is signed by `<n>` of the `<N>` validators
  of set `<valset_hash>` declared by the reviewer (`<set_source>`)”.

Avec k ≥ 2 groupes, la proposition joint les k morceaux par `,␣` et, devant le
dernier, par `␣et␣` (anglais `,␣` et `␣and␣`). Le premier morceau est « les
blocs `<hauteurs>` sont signés par `<n>` des `<N>` validateurs du jeu
`<valset_hash>` que le réviseur déclare (`<set_source>`) » (“blocks
`<hauteurs>` are signed by `<n>` of the `<N>` validators of set
`<valset_hash>` declared by the reviewer (`<set_source>`)”), les suivants
« les blocs `<hauteurs>` par `<n>` des `<N>` validateurs du jeu
`<valset_hash>` que le réviseur déclare (`<set_source>`) » (“blocks
`<hauteurs>` by …”) ; pour un groupe d'un seul certificat, « le bloc `<h>` est
signé par », « le bloc `<h>` par » (“block `<h>` is signed by”, “block `<h>`
by”). `<hauteurs>` : les hauteurs des certificats du groupe, croissantes,
jointes par `,␣` et, devant la dernière, par `␣et␣` (`␣and␣`).

`PeriodSubmitted` n'existe que si le contrat a vérifié le seuil du jeu
d'approbateurs assigné à l'organisation (R3 F36) ; l'énoncé ne le dit pas
parce que le code à l'adresse de l'ancre n'est pas prouvé par la version 0
(R3 NV7, section 17).

### 11.8 Ce que le contrôle 8 ne prouve pas

La légitimité du jeu de validateurs (le réviseur la déclare, R3 NV5) ; le code
des contrats aux adresses de l'ancre (R3 NV7) ; un fait d'état : appartenance
d'une adresse au `CuratorSet` à un instant, non-révocation d'une clé
d'enregistreur (absence de `RecorderRevoked`), dernière période du journal ;
l'absence d'un événement (le `logsBloom` du bloc n'est pas engagé, R3 F5,
conséquence 8) ; le lien entre `transaction_hash` et le reçu (l'index est
engagé par la clé du trie, le hachage de transaction ne l'est pas, R3
conséquence 6) ; l'heure réelle de la clôture (EX-11.18). Ce que CT-4 doit
livrer pour ce contrôle est en section 13.

## 12. Fichier d'ancres de confiance

### 12.1 Ce qui est de confiance, contrôle par contrôle

Le fichier d'ancres est la seule entrée que le vérificateur croit ; il croit
aussi son propre code et ses primitives cryptographiques (section 3.1). Ce
que le résultat suppose en outre est dit en 3.1 et 7.8. Le fichier d'ancres
est préparé et contrôlé par le réviseur.

**EX-12.1** Le vérificateur lit les ancres dans le seul fichier que désigne
l'option de la section 8. Il NE DOIT PAS lire d'ancre dans le répertoire du
dossier, dans une partie, dans le fichier d'en-têtes, dans une variable
d'environnement, dans le magasin de certificats du système ni sur le réseau ;
un fichier d'ancres placé dans le dossier est un fichier non déclaré, ignoré
(CT-1 §11.1). Sans fichier d'ancres, aucune vérification qui exige une ancre
ne s'exécute (raison `ancre_absente`), et un dossier CT-1 garde le verdict
qu'il avait avant CT-6 (section 6).

La table 3.3 dit, contrôle par contrôle, ce qui vient du dossier et ce qui
vient du fichier d'ancres. Le fichier d'en-têtes Bitcoin n'est ni l'un ni
l'autre : c'est une entrée à part, crue seulement au travers de O-5
(EX-10.4). Les intermédiaires et les CRL qu'un fichier d'ancres contient ne sont pas crus
pour autant : ils sont vérifiés comme ceux du jeton (T-7, T-10). Seuls le
certificat d'une autorité (sa clé et son nom), les déclarations de
non-révocation, le statut qualifié, le point de contrôle, l'identifiant de
chaîne, les adresses, les jeux de validateurs et les clés d'enregistreur sont
pris tels quels ; une CRL du fichier d'ancres l'est aussi, sans vérification
de sa signature, pour retirer la confiance au certificat d'une autorité
qu'elle liste (EX-9.16) : elle ne peut qu'ôter une confiance, jamais en
donner.

### 12.2 Format

Schéma : `spec/schemas/ancres-confiance-v0.schema.json` (JSON Schema draft
2020-12). Toutes les clés sont présentes ; une ancre que le réviseur ne fournit
pas vaut `null` (`bitcoin`, `registry`) ou une liste vide.

| Clé | Contenu |
|---|---|
| `version` | `0` |
| `label`, `prepared_by`, `prepared_at` | nom du jeu d'ancres, auteur, instant de préparation (horodatage CT-1 §3) ; non repris dans le rapport (7.1) |
| `tsa_authorities[]` | `name` ; `certificate` (PEM, un certificat) ; `intermediates` (PEM, au plus 8, non crus) ; `accepted_policies` (OID, ou `null` pour toute politique) ; `qualified` (`null`, ou `{framework: "eidas" \| "zertes", valid_from, valid_to \| null, source}`) ; `source` |
| `revocation.crls[]` | CRL complètes en PEM (au plus 64) |
| `revocation.statements[]` | `{certificate_sha256, not_revoked_at, method: "ocsp" \| "crl" \| "autre", source}` : le réviseur atteste avoir constaté la non-révocation du certificat à cet instant |
| `bitcoin` | `null`, ou `{network: "mainnet" \| "regtest", checkpoint: {height, hash}, min_confirmations, source}` ; `hash` dans l'ordre d'affichage de Bitcoin Core |
| `registry` | `null`, ou `{chain_id, contracts: {period_registry, attestation_registry, recorder_registry}, validator_sets[]: {from_height, to_height \| null, validators[]: {id, pubKeyHex}, source}, source}` |
| `recorders[]` | `{org_id, journal_id, key_id, public_key, chain_key \| null, source}` |

### 12.3 Exemple complet

L'autorité de l'exemple est une AC ECDSA P-256 produite le 2026-10-22 pour ce
document, sans autre usage ; la CRL est la sienne, vide. Le point de contrôle
Bitcoin est le bloc 966143, valeur `defaultAssumeValid` de Bitcoin Core au
commit `152a553` (R2-F51) ; le registre et les validateurs sont ceux du réseau
de développement ; les clés d'enregistreur sont celles des vecteurs de CT-1
§13, avec les clés de chaîne de l'annexe A. Le fichier est valide contre le
schéma (`ajv-cli` 5, `--spec=draft2020 --strict=true`).

<!-- schema: ancres-confiance -->
```json
{
  "version": 0,
  "label": "Ancres d'exemple de CT-6 §12",
  "prepared_by": "Réviseur d'exemple",
  "prepared_at": "2026-11-10T08:00:00.000Z",
  "tsa_authorities": [
    {
      "name": "AC d'exemple CT-6",
      "certificate": "-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJDSDEaMBgG\nA1UECgwRQXV0b3JpdGUgZGV4ZW1wbGUxGTAXBgNVBAMMEEFDIGRleGVtcGxlIENU\nLTYwHhcNMjYxMDIyMjEzMDI4WhcNMzYxMDE5MjEzMDI4WjBEMQswCQYDVQQGEwJD\nSDEaMBgGA1UECgwRQXV0b3JpdGUgZGV4ZW1wbGUxGTAXBgNVBAMMEEFDIGRleGVt\ncGxlIENULTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ/dLncElGnZaDYm0Ut\nyIBmERobTp0mln42olw8P41gN4KKQxxHCxT5UME98ZnQ2M/ATR10VDMoSYeWlPqc\nJGoYo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E\nFgQU5gkLnwArufhMLSLGQhNTxt/pN1YwCgYIKoZIzj0EAwIDSAAwRQIgM577tJFw\nyzTd+ChfGFNa8hYXSZ4sCrnNnB7Vp0bikCgCIQDjfhd00SrQ8BlejEeTPw46ewXW\ntPe1jz7d8XXbsXncTQ==\n-----END CERTIFICATE-----\n",
      "intermediates": [],
      "accepted_policies": [
        "0.4.0.2023.1.1"
      ],
      "qualified": {
        "framework": "zertes",
        "valid_from": "2026-10-22T00:00:00.000Z",
        "valid_to": null,
        "source": "exemple : statut que le réviseur aurait lu dans la liste de confiance suisse selon ses règles de schéma (numéro de séquence, date d'émission)"
      },
      "source": "exemple : autorité produite le 2026-10-22 pour illustrer ce format ; sans valeur"
    }
  ],
  "revocation": {
    "crls": [
      "-----BEGIN X509 CRL-----\nMIHbMIGDAgEBMAoGCCqGSM49BAMCMEQxCzAJBgNVBAYTAkNIMRowGAYDVQQKDBFB\ndXRvcml0ZSBkZXhlbXBsZTEZMBcGA1UEAwwQQUMgZGV4ZW1wbGUgQ1QtNhcNMjYx\nMDIyMjEzMDI4WhcNMjYxMTIxMjEzMDI4WqAOMAwwCgYDVR0UBAMCAQEwCgYIKoZI\nzj0EAwIDRwAwRAIgFrae/DT/noi7stnJMjelvdDj+NK5uq55rz8xmPK67Q0CIDAA\nbsNo2sCmpxaOpzzIUt7WjcURuPIVRwJRvwo38J1/\n-----END X509 CRL-----\n"
    ],
    "statements": []
  },
  "bitcoin": {
    "network": "mainnet",
    "checkpoint": {
      "height": 966143,
      "hash": "0x00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3"
    },
    "min_confirmations": 6,
    "source": "bloc 966143, valeur defaultAssumeValid de Bitcoin Core (src/kernel/chainparams.cpp, commit 152a553), à recouper avec le nœud du réviseur"
  },
  "registry": {
    "chain_id": "noortrace-2124-dev",
    "contracts": {
      "period_registry": "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
      "attestation_registry": "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8",
      "recorder_registry": "0xbec49fa140acaa83533fb00a2bb19bddd0290f25"
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
        "source": "validators.json du réseau de développement (test/fixtures/certificat-commit/validators.json), clés publiques seulement"
      }
    ],
    "source": "réseau de développement de chain/README.md ; adresses des transactions de déploiement des blocs 8316 à 8328"
  },
  "recorders": [
    {
      "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
      "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
      "key_id": "rec-test-01",
      "public_key": "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
      "chain_key": "0xaa2a59656361352e96ef2eed355316ef8b29dab7",
      "source": "clé de test de CT-1 §13 ; clé de chaîne de l'annexe A"
    },
    {
      "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
      "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
      "key_id": "rec-test-02",
      "public_key": "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
      "chain_key": "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49",
      "source": "clé de test de CT-1 §13 ; clé de chaîne de l'annexe A"
    }
  ]
}
```

### 12.4 Vérifications N-1 à N-4

| Id | Vérification | En anglais | Effet d'un défaut |
|---|---|---|---|
| N-1 | Fichier d'ancres | anchors file | entrée inutilisable, code 2 |
| N-2 | Fichier d'en-têtes | headers file | entrée inutilisable, code 2 |
| N-3 | Clés d'enregistreur | recorder keys | échec du contrôle 6 |
| N-4 | Clé de chaîne | chain key | échec du contrôle 8 |

N-1 et N-2 ne figurent pas dans `checks` : réussies, elles ne laissent rien à
rapporter ; en défaut, elles produisent le rapport d'erreur.

**EX-12.2 (N-1, fichier d'ancres)** Le fichier est lisible, au plus 16 Mio
(EX-4.13), conforme à son schéma, et cohérent : chaque PEM se décode en un
seul certificat X.509 v3 ou une seule CRL lisibles selon 9.3 ; les dates
existent (CT-1 §3) ; dans chaque déclaration `qualified`, `valid_from` ne
suit pas `valid_to` quand celui-ci n'est pas nul ; aucun certificat ni CRL
n'encode une valeur `DEFAULT` (EX-9.21) ; les noms d'autorités sont distincts ; chaque jeu de
validateurs se charge comme le nœud le charge (identifiants non vides et
distincts, clés exploitables et toutes distinctes, `scripts/verify/README.md`,
point 2) ; dans `registry.validator_sets`, `from_height ≤ to_height` et les
intervalles ne se recouvrent pas ; un couple (`org_id`, `journal_id`,
`key_id`) de `recorders` est unique. Sinon l'entrée est inutilisable : aucun
contrôle n'est exécuté ; code 2, type `ancres_inutilisables`, `error.check` =
`N-1` (EX-4.10, EX-4.12) ; le message nomme le défaut.

**EX-12.3 (N-2, fichier d'en-têtes)** Le fichier est lisible, au plus 64 Mio
et 200 000 en-têtes (EX-4.13), conforme à son schéma, et
`start_height + n − 1 < 2³²`. Sinon l'entrée est inutilisable : code 2, type
`taille_depassee` pour une limite et `entree_illisible` sinon, `error.check`
= `N-2` (EX-4.12).

**EX-12.4 (N-3, clés d'enregistreur ; complète le contrôle 6)** N-3 ne
s'exécute et ne figure au rapport que si `recorders` contient au moins une
entrée des `org_id` et `journal_id` du dossier (EX-5.6). Elle est alors
`non_execute`, raison `prerequis_en_echec`, si `cles.json` ne remplit pas la
première partie de E-8 (CT-1 §11.4) : conformité à son schéma, `org_id` et
`journal_id` égaux à ceux de l'événement, `key_id` et `public_key` uniques,
`valid_to ≥ valid_from`. Pour chaque clé de `cles.json` qui signe un événement du dossier ou le
manifeste, et dont le triplet (`org_id`, `journal_id`, `key_id`) figure dans
`recorders` : la `public_key` de l'ancre égale celle de `cles.json`. Statut :
`echoue` si une clé diffère ; sinon `reussi` si au moins une clé a été
comparée ; sinon `non_execute` (`ancre_absente`). N-3 en échec fait échouer le
contrôle 6 ; N-3 non exécutée ne change pas son statut. Une clé confirmée par
N-3 a la provenance `ancres` de l'énoncé (EX-6.8).

**EX-12.5 (N-4, clé de chaîne ; complète le contrôle 8)** N-4 ne s'exécute et
ne figure au rapport que si P-1 a réussi (la clé du manifeste est alors
établie, EX-5.4), que l'ancre déclare une `chain_key` non nulle pour la clé du
manifeste (mêmes `org_id` et `journal_id`, `key_id` =
`manifeste.recorder_key_id`) et que les parties du contrôle 8 sont présentes.
Elle est `non_execute`, raison `prerequis_en_echec`, si l'entrée `ancre` n'a
pas passé R-6 et R-7 ; et, avec la raison que R-5 porte pour lui (EX-5.5), si
R-5 n'a pas réussi pour le certificat du bloc de l'entrée `ancre` : sans
quorum vérifié, l'émetteur lu n'est pas authentifié. Sinon l'émetteur de
l'ancre (`topics[2]`, 20 derniers octets) égale cette `chain_key` : `reussi`,
ou `echoue` s'il diffère. N-4 en échec fait échouer le contrôle 8 ; non
exécutée, elle ne change pas son statut.

### 12.5 Où le réviseur prend ses ancres

| Ancre | Source | Précautions |
|---|---|---|
| Autorité d'horodatage (UE) | La liste des listes de la Commission, https://ec.europa.eu/tools/lotl/eu-lotl.xml, puis la liste nationale du prestataire ; service de type `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` ; son identité numérique de service sert de `certificate` (R1 F4.01, F4.02, F4.03, F4.05) | L'identité de service peut être une AC intermédiaire (Sectigo : l'AC « Qualified Time Stamping CA R35 » de la liste espagnole, R1 F7.05) ; l'authenticité de la liste repose sur sa signature et sur les certificats publiés au Journal officiel (R1 F4.01), signature que le digest R1 n'a pas vérifiée (son point non vérifié 7). Vérifier que le service était `granted` et son certificat valide à `genTime` : le vérificateur ne contrôle ni les dates du certificat de l'ancre (sauf unité épinglée, dont les dates sont contrôlées comme celles du certificat signataire) ni sa révocation, sauf si une CRL du fichier d'ancres la porte (EX-9.13, EX-9.16). |
| Autorité d'horodatage (Suisse) | https://trustedlist.tsl-switzerland.ch/tsl-ch.xml ; URI propres au schéma suisse ; « recognised » y vaut « qualified » (R1 F4.09, F4.10) | La Suisse n'est pas dans la liste européenne (R1 F4.08) ; Swisscom opère une AC pour la liste suisse (TSS CA 4) et une autre pour la liste autrichienne (TSS CA 4.1) (R1 F7.09, F7.10) ; le certificat qui signe la liste suisse expire le 2026-12-15 (R1 F4.11) : garder une copie datée de la liste. |
| `qualified` | Pour `eidas` : résultat de la procédure ETSI TS 119 615 §4.6 à l'instant du jeton, statut `granted` à `genTime`, historique compris (R1 F4.04, F4.06, F4.07). Pour `zertes` : statut du service `…/TSA/QTST` de la liste suisse à `genTime`, selon ses règles de schéma (R1 F4.09, F4.10) ; TS 119 615 §4.6 ne s'applique pas hors de l'UE. | Écrire dans `source` le territoire, le numéro de séquence et la date d'émission de la liste lue (R1, conséquence 9). |
| `revocation.crls` | Point de distribution de CRL de l'AC, relevé après `genTime` ; Sectigo publie certificats et CRL (R1 F7.02) | Une AC qui ne publie que de l'OCSP (Swisscom pour ses AC d'horodatage, R1 F7.07) se traite par une déclaration (`statements`). |
| `bitcoin.checkpoint` | Le nœud du réviseur (`getblockhash`, ordre d'affichage) recoupé avec une source indépendante ; hauteur un peu inférieure à celles des attestations, et comprise dans le fichier d'en-têtes (sinon O-5 n'est pas exécutée, EX-10.9, règle 3) | Le code de Bitcoin Core (branche principale, commit `152a553`) ne contient plus de points de contrôle (R2-F51 ; version publiée qui les a retirés : non vérifié, point non vérifié 6 du digest R2) et son travail minimal de chaîne n'est qu'une protection contre le déni de service (R2-F52) : le point de contrôle est un choix du réviseur. Sur `mainnet`, le fichier d'en-têtes doit commencer au plus tard à `2016 × ⌊c ÷ 2016⌋` (EX-10.9, règle 5) ; un en-tête fait 80 octets. Si le fichier joint par l'exportateur ne contient pas `c`, le réviseur peut produire le sien depuis son nœud (EX-13.13). |
| `registry.validator_sets` | Le `validators.json` du réseau, obtenu d'au moins deux opérateurs de validateurs indépendants (partenaires), comparé par son hachage (EX-11.8) | La provenance du jeu n'est pas prouvable par le registre lui-même (R3 NV5). |
| `registry.contracts`, `chain_id` | Les transactions de déploiement et leurs blocs certifiés, publiés par CT-4 (section 13) ; la ligne de règles de genèse pour `chain_id` (`chain/README.md`) | Les certificats des blocs de déploiement sont élagués au-delà de la fenêtre de rétention (R3, conséquence 9) : ils doivent avoir été capturés. Ces publications viennent du fournisseur du registre, que le contrôle 8 ne croit pas : recoupez l'adresse avec sa transaction de déploiement, dans un bloc certifié par le jeu de validateurs obtenu des partenaires, et le code d'initialisation avec la compilation de `contracts/`. Sinon, H3 et H7 reposent sur NOORTRACE pour ce point. |
| `recorders` | Procès-verbal d'inscription de la clé (CT-2 EX-11.13) et cérémonie des clés (CT-7) | — |

## 13. Exigences imposées à CT-4 et CT-5

Les cinq parties réservées sont produites par l'ancrage (CT-5) et le registre
(CT-4). Ce qui suit est ce que le vérificateur exige d'elles ; CT-4 et CT-5
s'y conforment et le reprennent dans leurs propres exigences.

### 13.1 CT-5, jeton RFC 3161

**EX-13.1** La requête porte `messageImprint` = (SHA-256, `periodHash`),
`certReq` = vrai, et un nonce aléatoire (`openssl ts -query -digest
<periodHash sans le préfixe 0x> -sha256 -cert`, R1 F6.01) ; avec `certReq`
vrai, la TSA place son certificat dans le jeton (R1 F1.19), et T-4 ne dépend
pas de l'ancre.

**EX-13.2** À la réception, CT-5 vérifie `status` 0 ou 1 (R1 F1.02), l'égalité
de `messageImprint` et du nonce avec la requête (R1 F1.14, F1.16), puis T-1 à
T-9 à l'heure courante et à `genTime`, et T-10 dès qu'il dispose de la preuve
de non-révocation de EX-13.12 ; il consigne l'acquisition (instant, service,
nonce). Le nonce ne se contrôle qu'à ce moment.

**EX-13.3** CT-5 n'enregistre que le `TimeStampToken`, en DER, sans le
réencoder (`openssl ts -reply -token_out`, R1 F6.02), comme partie
`jeton_rfc3161` ; la réponse n'est pas conservée dans le dossier.

**EX-13.4** Le service est celui d'un prestataire qualifié (architecture,
« Ancrage ») ; CT-5 respecte ses contraintes d'usage, par exemple au moins
15 s entre deux requêtes scriptées chez Sectigo (R1 F7.01).

**EX-13.12** Peu après `genTime`, CT-5 capture et publie, hors du dossier, la
CRL (ou, à défaut, la réponse OCSP) de chaque certificat du chemin du jeton,
émise après `genTime`, avec sa source et l'instant de la capture. Le
réviseur la place dans `revocation.crls`, ou consigne une déclaration
(`statements`) à partir d'une réponse OCSP. Motif : T-10 n'aboutit qu'avec une
CRL de `thisUpdate` postérieur ou égal à `genTime`, ou une déclaration ; des
années plus tard, l'AC peut ne plus en publier (la validation à long terme
est hors de la version 0, section 17), et CT-5 ne peut pas l'ajouter au champ
`crls` du jeton sans le réencoder (EX-13.3).

### 13.2 CT-5, preuve OpenTimestamps

**EX-13.5** CT-5 horodate le fichier qui contient exactement `P_M ‖ C_M`
(empreinte de fichier = `periodHash`, opération `08`, EX-10.1), auprès d'au
moins deux calendriers (le client officiel en exige deux par défaut, R2,
conséquence 10).

**EX-13.6** CT-5 complète la preuve (`GET /timestamp/<engagement>`, R2-F69,
R2-F75) jusqu'à obtenir une attestation Bitcoin, puis réexporte les dossiers
de la période ; il faut compter des heures (6 à 12 h entre transactions et 6
confirmations par défaut côté serveur, R2-F73, R2-F74). Une preuve exportée
avant reste lisible et rend le contrôle 5 non exécuté (O-7). Les opérations
restent dans le profil `{f0, f1, 08}` (EX-10.7).

**EX-13.7** CT-5 PEUT joindre au dossier, hors des parties, un fichier
`entetes-bitcoin.json` (10.3) ; ce fichier n'est pas crédité (EX-10.4). Le
vérificateur ne le lit que si le réviseur le désigne par `--entetes-bitcoin`
(EX-4.1, EX-4.5).

**EX-13.13** Le fichier d'en-têtes que CT-5 joint commence à la hauteur
`max(0, 2016 × (⌊h ÷ 2016⌋ − 1))`, `h` étant la plus petite hauteur attestée, et va au
moins jusqu'à `h + 11` (borne de EX-10.13). CT-5 ne connaît pas le point de
contrôle du réviseur : ce début couvre tout point de contrôle `c` compris entre
lui et `h`, règle 5 de EX-10.9 comprise (le premier réajustement au-dessus de
`c` trouve l'en-tête de 2016 hauteurs plus bas). Un réviseur dont le point de
contrôle tombe hors du fichier obtient O-5 non exécutée (`ancre_absente`) et
peut produire son propre fichier depuis son nœud.

### 13.3 CT-4, registre

**EX-13.8** Pour chaque transaction de registre que le dossier prouvera
(`registerRecorder` de chaque clé qui signe dans le journal, `anchor`,
`submitPeriod`), dès que le reçu est rendu, l'exportateur capture : l'en-tête
(`eth_getBlockByNumber(h, false)`, les dix champs de 11.2.1) ; le reçu de
**chaque** transaction du bloc par `eth_getTransactionReceipt`, jamais par
`eth_getBlockReceipts`, qui rend une liste vide (R3 F29) ; le certificat par
`noor_getCommitCertificate(h)` auprès d'un validateur, jamais d'un suiveur qui
ne fait que relayer (R3 F45, `chain/docker/README.md`), en réessayant sur la
réponse transitoire « not yet persisted » (R3 F44, `chain/README.md`).
Motif de l'immédiateté : un validateur ne garde que 300 000 hauteurs de
certificats, soit environ 73 h à la cadence de 1,14 bloc/s mesurée sur le
réseau de développement (R3 F43, F46).

**EX-13.9** `registre.json` porte au moins l'entrée `cloture`, l'entrée
`ancre`, et l'entrée `inscription` de la clé qui signe le manifeste sous la
clé de chaîne qui signe l'ancre (sans elle, AV-R-1, ou échec de R-10 si
seule une ancienne inscription est jointe, EX-11.19) ; pour les autres clés
qui signent dans le dossier (événement, voisins, décisions), la dernière
inscription de chacune ; au plus 8 entrées `inscription` en tout (schéma
`registre-v0`), les inscriptions antérieures d'une clé réinscrite n'étant pas
nécessaires ; hexadécimal en minuscules ; aucune valeur d'état
(`getPeriod`, `lookup`, `recorderByPubKey`), qui n'est pas prouvable (R3 F41).

**EX-13.10** `validateurs.json` reprend le `validators.json` du réseau et sa
provenance, jamais le champ `validatorSet` de la réponse du nœud (R3 F20).

**EX-13.11** CT-4 publie, hors des dossiers et pour les réviseurs :
l'identifiant de chaîne, les adresses des contrats avec les blocs certifiés de
leurs transactions de déploiement (capturés avant leur élagage, R3,
conséquence 9), et les jeux de validateurs avec leurs hauteurs de validité.
CT-4 DEVRAIT prévoir une rétention étendue chez les validateurs partenaires
(`NOOR_BFT_CERT_RETENTION_HEIGHTS`, R3 F43).

## 14. Binaire

Le binaire est construit en phase 2 (étape 2 du plan) ; cette section en fixe
les règles. L'implémentation de référence JavaScript
(`scripts/verify/dossier.mjs`) applique les mêmes vérifications et sert
d'oracle aux vecteurs.

### 14.1 Langage et dépendances

**EX-14.1** Le binaire est écrit en Go, sans cgo (`CGO_ENABLED=0`). Ses seules
dépendances sont la bibliothèque standard, `golang.org/x/crypto` v0.58.0
(`sha3.NewLegacyKeccak256` pour keccak256, que la bibliothèque standard
n'offre pas, R4 F3.03 ; `cryptobyte` pour la lecture DER, R4 F5.05) et
`github.com/decred/dcrd/dcrec/secp256k1/v4` v4.4.1 (`ecdsa.RecoverCompact`,
R4 F3.04, F3.05), vendorisées, avec les lignes `go.sum` attestées par la
base de sommes (R4 F3.10) :

```text
golang.org/x/crypto v0.58.0 h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=
golang.org/x/crypto v0.58.0/go.mod h1:Xh+kl5A+M0gMiWDytH2Hhr5Z7WbNCpv/eB/EFgfSk+w=
github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 h1:5RVFMOWjMyRy8cARdy79nAmgYw3hK/4HUq48LQ6Wwqo=
github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1/go.mod h1:ZXNYxsqcloTdSy/rNShjYzMhyjf0LaoftYK0p+A3h40=
github.com/decred/dcrd/crypto/blake256 v1.1.0 h1:zPMNGQCm0g4QTY27fOCorQW7EryeQ/U0x++OzVrdms8=
github.com/decred/dcrd/crypto/blake256 v1.1.0/go.mod h1:2OfgNZ5wDpcsFmHmCK5gZTPcCXqlm2ArzUIkw9czNJo=
```

Licences : BSD à trois clauses (Go et `x/crypto`, avec un fichier `PATENTS`)
et ISC (decred), toutes deux de catégorie A pour la fondation Apache, donc
compatibles avec une diffusion sous Apache-2.0 (R4 F3.02, F3.04, F3.11). La
base des vulnérabilités de Go ne vise ni `sha3` ni le module decred ; le seul
avis visant `cryptobyte` (GO-2022-0229, panique sur architectures 32 bits) est
corrigé depuis 2020 (R4 F3.13).

**EX-14.2** Adaptateur secp256k1 : une signature EIP-191 `r ‖ s ‖ v` devient
`code ‖ r ‖ s` avec `code` = 27 + (`v` − 27) pour `v` dans {27, 28}, toute
autre valeur étant refusée ; l'empreinte passée fait exactement 32 octets
(`RecoverCompact` tronque une entrée plus longue sans erreur, R4 F3.07,
F3.08) ; la règle « S bas » est contrôlée par le vérificateur, puisque
`RecoverCompact` accepte un S haut (R4 F3.06, F3.08), là où CT-1 (E-9) et
noorcore (R3 F12) l'exigent.

**EX-14.3** Version de Go : exactement go1.27.3, inscrite dans `go.mod`
(lignes `go` et `toolchain`). Au 2026-10-22, le minimum maintenu est go1.26.10
ou go1.27.3 ; go1.24.7, celle de l'environnement de recherche, n'est plus
maintenue et reste exposée à GO-2025-4011 et GO-2026-5972 (R4 F1.28, F3.14).
Le rapport porte la version de Go (`runtime.Version()`) et celle du binaire.

**EX-14.4** La validation de chemin de T-7 est faite par le code du
vérificateur. `crypto/x509` PEUT servir à lire les certificats et à vérifier
une signature, à condition qu'une relecture stricte des octets reçus
applique en plus le profil de 9.3 et EX-9.21 (valeurs `DEFAULT` encodées,
que `crypto/x509` accepte) et lise les noms selon EX-9.4 (`crypto/x509`
refuse un nom d'un type de chaîne qu'il ne lit pas, que CT-6 admet) ; `Certificate.Verify` n'est jamais appelé avec
`Roots` nul ni avec `SystemCertPool()` : le vérificateur de la plate-forme
serait alors employé sous Windows et macOS, et peut récupérer des émetteurs
AIA sur le réseau (R4 F2.02 à F2.06 ; déduit du code et des documentations,
non observé : point non vérifié 1 du digest R4).

### 14.2 Absence de réseau, et sa preuve

**EX-14.5** Le code n'importe ni `net/http`, ni `crypto/tls`, ni `os/exec`. La
CI le prouve à chaque construction (R4 F2.11 à F2.15) :

```bash
go list -deps ./... | grep -E '^(net/http|crypto/tls|os/exec)$'          # sortie vide exigée
go tool nm <binaire> | grep -E ' net\.\(\*(Resolver|Dialer)\)'          # sortie vide exigée
unshare -n <binaire> <arguments des vecteurs>                            # même code de retour qu'hors isolement
strace -f -qq -e trace=%network -e signal=none -o trace.txt <binaire> …  # trace.txt vide exigé
```

`net` et `net/url` peuvent figurer dans `go list -deps` parce que
`crypto/x509` les importe, sans code de résolution lié au binaire (R4 F2.11).
`unshare -n` a été essayé en superutilisateur ; la forme sans privilège
`unshare -rn` n'a pas été essayée (point non vérifié 4 du digest R4).

### 14.3 Construction reproductible

**EX-14.6** Recette de référence, depuis un clone au commit publié ou depuis
l'archive des sources de ce commit :

```bash
GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
GOOS=<os> GOARCH=<arch> GOAMD64=v1 \
go build -trimpath -buildvcs=false -ldflags='-buildid= -X main.version=<version>' -o <sortie> ./<paquet principal>
```

Entrées pertinentes, et seules entrées : le commit, la version exacte de Go,
`GOOS`, `GOARCH` et le niveau d'architecture, le répertoire `vendor/` avec
`modules.txt`. Motifs : `-trimpath` retire les chemins locaux (sans lui, le
binaire d'essai de R4, vérificateur indépendant de CT-1, portait 13 fois son
chemin absolu, R4 F1.05, F1.16) ; cgo désactivé
retire la chaîne C de l'hôte (R4 F1.04) ; `GOENV=off` et `GOFLAGS` neutralisent
la configuration de l'utilisateur (R4 F1.13) ; `GOTOOLCHAIN=local` interdit le
téléchargement d'une autre chaîne (R4 F1.18) ; `-buildvcs=false` rend
équivalents l'archive et le clone, l'estampille VCS changeant le binaire dès
qu'un fichier est modifié (R4 F1.09, F1.17) ; `-mod=vendor` est fixé parce que
les modes vendor et module donnent des binaires différents (R4 F1.22) ;
`GOAMD64` change le binaire (R4 F1.16) ; `-buildid=` vide l'identifiant de
construction (R4 F1.12).

**EX-14.7** L'image de conteneur de construction est désignée par son
empreinte (`golang:<version>@sha256:<empreinte>`, R4 F1.26), fixée dans le
fichier de construction en phase 2 et publiée avec chaque version ; les
actions de CI sont épinglées par SHA de commit (R4 F1.27).

**EX-14.8** Deux constructions indépendantes (deux machines ou deux
conteneurs, chemins, utilisateurs et caches différents) DOIVENT donner les
mêmes octets ; la CI construit deux fois et compare les SHA-256. R4 a observé
des octets identiques sur une même machine, avec des chemins et des caches
différents, pour le vérificateur indépendant de CT-1 et pour une
construction vendorisée sous `unshare -n` (R4 F1.16, F1.22) ; deux machines ou
deux utilisateurs n'ont pas été essayés. Les archives publiées fixent l'heure
des entrées à la date du commit (`SOURCE_DATE_EPOCH`), l'ordre des entrées et
des propriétaires nuls (R4 F1.07, F1.24 ; Go 1.24.7 ne lit pas cette
variable, R4 F1.25, Go 1.26.9 non plus ; non vérifié pour go1.27.3).

### 14.4 Diffusion, licence, versions

**EX-14.9** Chaque version publie : les binaires (au moins `linux/amd64` et
`linux/arm64`), `SHA256SUMS`, la signature minisign de `SHA256SUMS` dont le
commentaire de confiance porte la version et la date (R4 F4.02), la recette de
14.3, la sortie attendue de `go version -m` (R4 F1.11), et `LICENCES-TIERCES`
(textes de Go, `x/crypto` avec `PATENTS`, decred). Le réviseur reconstruit et
compare par `sha256sum --strict -c SHA256SUMS` (R4 F4.01). Une attestation
de provenance (`actions/attest`), vérifiable hors ligne par `gh attestation
verify --bundle … --custom-trusted-root …` (R4 F4.06 à F4.08), et une
publication GitHub immuable (étiquette et fichiers verrouillés, attestation
de publication contrôlée par `gh release verify` et `gh release
verify-asset`, R4 F4.09 ; vérification hors ligne de cette attestation : non
vérifié) PEUVENT s'y ajouter ; la reproductibilité reste le contrôle fort
(R4 F1.08).

**EX-14.10** Le binaire et son code sont publiés sous licence Apache-2.0 ; la
diffusion d'un binaire reproduit les avis des licences tierces (clause binaire
BSD-3, avis ISC, R4 F3.02, F3.04) et le fichier NOTICE du projet (Apache-2.0
§4(d), R4 F3.12).

**EX-14.11** Un vérificateur de version 0 lit les dossiers, les ancres et les
en-têtes de version 0. Une autre version dans `dossier.json` fait échouer D-1,
et une autre version dans une partie fait échouer la vérification de cette
partie (CT-1 §11.4 pour les parties de CT-1 ; T-1, O-1, R-1, R-3 pour les
parties réservées) : code 1, comme pour toute partie non conforme, ce qui
garde le verdict des dossiers de CT-1, tous de version 0. Une autre version
du fichier d'ancres ou du fichier d'en-têtes rend l'entrée inutilisable
(N-1, N-2 : code 2), puisque ce ne sont pas des pièces du dossier. Un vérificateur
de version 1 lira les dossiers de version 0 et leur appliquera les règles de
version 0 (CT-1 §14, décision 5). La CI lance `govulncheck` sur le code et sur
chaque binaire publié, en lisant son code de retour hors du mode `-json`, qui
rend toujours 0 (R4 F3.15).

## 15. Sûreté du vérificateur

### 15.1 Bornes

**EX-15.1** Le vérificateur lit chaque entrée dans la limite de taille de la
table EX-4.13, puis applique, pendant l'analyse, les bornes ci-dessous ; une
partie qui en dépasse une est inexploitable et fait échouer la vérification
qui la porte (T-1, O-1, R-1, R-3, ou celle de CT-1 §11.4) ; un fichier
d'ancres ou d'en-têtes qui en dépasse une rend l'entrée inutilisable (N-1,
N-2).

| Structure | Borne |
|---|---|
| jeton RFC 3161 | profondeur DER 32 ; 16 certificats dans le jeton ; chemin de 5 certificats au plus, ancre non comprise |
| preuve `.ots` | 255 opérations par chemin ; argument de 1 à 4096 octets ; message et résultat de 1 à 4096 octets ; charge d'attestation 8192 octets ; URI de 0 à 1000 octets ; `varuint` 9 octets |
| `registre.json` | 16 entrées ; 256 reçus par bloc ; 256 journaux par reçu ; 4 sujets par journal |
| `certificat-commit.json` | 16 certificats ; 128 lignes de precommit ; ligne de 4 Mio |
| `validateurs.json`, ancre `registry` | 16 jeux de 128 validateurs |
| fichier d'ancres | 32 autorités, 8 intermédiaires chacune ; 64 CRL ; 256 déclarations ; 256 clés d'enregistreur |
| fichier d'en-têtes | 200 000 en-têtes |
| tout JSON | profondeur d'imbrication 128 (EX-4.13) |

Les bornes de la preuve `.ots` sont celles de la bibliothèque de référence
d'OpenTimestamps (R2-F13, R2-F18, R2-F19, R2-F20), sauf la borne de 9 octets et
la forme minimale des `varuint`, choix de cette spécification (la bibliothèque
n'en a pas, R2-F07). Les autres sont des choix de cette spécification,
au-dessus de ce que les parties produites par CT-4 et CT-5 atteignent (un
certificat mesuré fait de 7 075 à 7 782 octets, R3 F47) ; elles sont aussi
celles des schémas de la section 12 et de `registre-v0.schema.json`.

### 15.2 Aucune panique, aucune boucle non bornée

**EX-15.2** Toute récursion est bornée par le code (un débordement de pile ne
se rattrape pas en Go, R4 F5.10). Chaque contrôle s'exécute isolé ; une panique
rattrapée est rendue comme erreur interne du vérificateur (code de la section
8), jamais comme un statut `reussi`, `echoue` ou `non_execute`.

### 15.3 Fuzzing

**EX-15.3** Le binaire porte une cible de fuzzing par analyseur : jeton CMS et
`TSTInfo`, certificat et CRL, `.ots`, fichier d'en-têtes, `registre.json`,
lignes de certificat, fichier d'ancres, JSON et JCS de CT-1 ; corpus de
graines dans `testdata/fuzz/` (vecteurs de l'annexe A, exemples de CT-1 et
CT-2) ; `go test` rejoue le corpus à chaque CI, et une tâche bornée par
`-fuzztime` tourne sur AMD64 ou ARM64, seules architectures instrumentées
(R4 F5.01 à F5.03, pratique de sigstore-go, R4 F5.11).

### 15.4 Algorithmes refusés

SHA-1 et MD5 comme empreinte ou dans une signature, RSA de moins de 2048 bits
(T-5) ; SHA-1 n'est admis que comme identifiant de certificat (T-4).
Signature secp256k1 à S haut (R-5, et CT-1 E-9). Keccak-256 n'est employé que
là où l'EVM et noorcore l'imposent (`BFTBlockHash`, trie des reçus, journaux,
`anchorFingerprint`).

### 15.5 Attaques considérées

| Attaque | Parade | Vecteur (annexe A) |
|---|---|---|
| Rejeu d'un jeton d'horodatage sur un autre manifeste | T-2 : `hashedMessage` = `periodHash` recalculé | `invalide-t2-jeton-autre-manifeste` |
| Jeton d'une TSA que le réviseur n'accepte pas, ou expirée à `genTime` | T-7 | `invalide-t7-tsa-expiree` |
| Clé de TSA compromise | T-10 (`keyCompromise` invalide tous les jetons), y compris quand le réviseur a épinglé l'unité elle-même et que la CRL est dans son fichier d'ancres (EX-9.16) ; une révocation que le fichier d'ancres ne porte pas n'est pas vue | `invalide-t10-tsa-revoquee`, `invalide-t10-unite-epinglee-revoquee` |
| Rétrogradation d'algorithme | T-5 | `invalide-t5-sha1` |
| Preuve OpenTimestamps d'un autre manifeste | O-2 | `invalide-o2-preuve-autre-manifeste` |
| Chaîne d'en-têtes sans travail, ou d'un autre réseau | O-5 (travail, difficulté, réseau, point de contrôle) | `invalide-o5-chaine-sans-travail` |
| Attestation désignant un autre bloc | O-4 | `invalide-o4-mauvaise-hauteur` |
| Certificat d'une autre chaîne signé par le même jeu | R-4 | `invalide-r4-autre-chaine` |
| Jeu de validateurs substitué (certificat forgé, `validateurs.json` assorti) | R-2 : quorum calculé sur le jeu de l'ancre | `invalide-r2-jeu-substitue` |
| En-tête falsifié | R-6 : `BFTBlockHash` recalculé | `invalide-r6-entete-modifie` |
| Reçu falsifié qui garde le `blockHash` certifié | R-7 : racine des reçus recalculée (R3 F32) | `invalide-r7-recu-falsifie` |
| Événement émis par un autre contrat | R-8 | `invalide-r8-autre-contrat` |
| Clôture ou ancre d'une autre période | R-9 | `invalide-r9-cloture-autre-periode` |
| Ancre absente traitée comme réussie | Statuts de la section 6 : `non_execute` n'est jamais compté comme `reussi`, et l'énoncé ne reprend que les contrôles réussis | `valide-seq-7-complet-sans-ancres` |
| Ancre lue dans le dossier ou sur le réseau | EX-12.1, EX-14.4, EX-14.5 | contrôles de 14.2 |
| Analyseur piégé (longueurs, profondeur, octets en trop, formes non minimales) | 9.3, EX-10.2, 15.1, 15.3 | `invalide-t1-octet-en-trop`, `invalide-o1-octet-en-trop` |

## 16. Décisions de l'architecture touchées et alignement avec le dépôt

La décision qui touche l'architecture : **les trois ancres portent sur
`periodHash`**, et non sur SHA-256 de la racine (9.1). Les autres points
viennent des recherches du lot.

| Emplacement | Avant | Attendu | État |
|---|---|---|---|
| `ARCHITECTURE.md`, « Ancrage », point 2 | « Une requête RFC 3161 contenant SHA-256 de R » | « contenant `periodHash`, SHA-256 du manifeste préfixé (CT-1 §10.2), qui engage R, les bornes, la continuité, le journal et la clé » | fait |
| `ARCHITECTURE.md`, « Ancrage », point 3 | « `ots stamp` sur R » | « `ots stamp` sur le manifeste préfixé, d'empreinte `periodHash` » | fait |
| `ARCHITECTURE.md`, « Dossier et vérification », contrôle 4 | « égalité entre l'empreinte du jeton et SHA-256 de R » | « … et `periodHash` recalculé » | fait |
| `ARCHITECTURE.md`, « Dossier et vérification », contrôle 8 | « signé par un quorum du jeu de validateurs fourni » | « signé par un quorum du jeu de validateurs que le réviseur déclare dans ses ancres ; hachage du bloc recalculé (`BFTBlockHash`, pas celui d'Ethereum) ; racine des reçus recalculée » | fait |
| `ARCHITECTURE.md` et `README.md`, registre | — | dire que le hachage de bloc de noorcore n'est pas celui d'Ethereum, et qu'un certificat divulgue les transactions brutes de tout son bloc, y compris celles d'autres organisations (R3 F18, F47) | fait |
| `CT-1` §11.2, lignes `jeton-rfc3161.der` et `preuve.ots` | « sur SHA-256 de la racine », « de la racine » ; schéma « CT-5 » | « sur `periodHash` (CT-6 §9, §10) » ; formats fixés par CT-6 | fait (texte seulement) |
| `CT-1` §11.2, ligne `registre.json` | « Reçu de `submitPeriod` et de `anchor`, valeurs lues (`getPeriod`, `lookup`, `recorderByPubKey`) » | « Entrées de CT-6 §11.2.1 : en-têtes, tous les reçus du bloc, index ; aucune valeur d'état » | fait (texte seulement) |
| `CT-1` §11.2, lignes `certificat-commit.json` et `validateurs.json` | un certificat ; « jeu de validateurs du bloc » | un certificat par bloc (CT-6 §11.2.2) ; jeux déclarés avec hauteurs (§11.2.3) | fait (texte seulement) |
| `CT-1` §11.3, ligne 4 ; §11.4, dernier paragraphe | « égalité avec SHA-256 de la racine » ; « spécifiés par CT-5 et CT-4 » | « égalité avec `periodHash` » ; « spécifiés par CT-6 (T-, O-, R-) » | fait (texte seulement) |
| `CT-1` §11.4, `dossier.json` qui n'est pas du JSON | rangé sous D-1 (code 1) | entrée inutilisable, code 2 (`dossier_illisible`, EX-4.12, EX-5.2) ; un `dossier.json` qui est du JSON mais pas un index conforme reste un échec de D-1 (code 1) | fait (texte de CT-1 §11.4 aligné ; écart de CT-6 au comportement de la version CT-1 : aucun, celle-ci rendait déjà le code 2) |
| `chain/README.md`, « Rétention » | « ≈ 83 h à un bloc par seconde » | « ≈ 83 h à un bloc par seconde ; ≈ 73 h à la cadence de 1,14 bloc/s mesurée » (R3 F46) | fait |
| `scripts/verify/README.md`, « Ce que le vérificateur ne prouve pas » | `BFTBlockHash` non recalculé | renvoi au contrôle 8 de `dossier.mjs` (R-6, R-7), qui recalcule hachage de bloc et racine des reçus | fait |
| `NOTICE` | — | mention des licences tierces livrées avec le binaire (EX-14.10, R4 F3.12) | à faire en phase 2, avec le binaire |
| `ARCHITECTURE.md`, « Dossier et vérification », contenu du dossier | « le reçu de la transaction du registre avec le certificat de commit de son bloc et le jeu de validateurs de ce bloc » | « les entrées du registre (inscription de la clé, ancre, clôture) avec l'en-tête et tous les reçus de leurs blocs, le certificat de commit de chaque bloc, et le jeu de validateurs déclaré » | fait |
| `spec/README.md` | CT-6 « à écrire » ; cinq schémas | CT-6 en revue ; schémas de CT-6 (`ancres-confiance`, `entetes-bitcoin`, `registre`, `validateurs`, et celui du rapport) ; vecteurs `ct-6/` | fait |

## 17. Ce que cette version ne couvre pas

- **Le statut qualifié établi par le vérificateur** : la lecture des listes de
  confiance (ETSI TS 119 615 §4.6 pour l'UE, règles du schéma suisse pour
  ZertES) et la vérification de leurs signatures XAdES restent au réviseur,
  qui en écrit le résultat dans l'ancre (T-11).
- **OCSP**, les CRL delta ou partielles, les CRL indirectes : remplacés par une
  déclaration du réviseur (T-10).
- **DSA, EdDSA, SLH-DSA, XMSS, LMS**, que ETSI TS 119 312 exige des
  vérificateurs de jetons (R1 F3.06) : `non_execute` en version 0.
- **La validation à long terme** des jetons après la fin de validité du
  certificat de l'unité (réhorodatage, EN 319 421 annexe D, R1 F3.18) ;
  l'extension `privateKeyUsagePeriod` n'est pas lue.
- **Les opérations OpenTimestamps `02`, `03`, `67`, `f2`, `f3`**, les
  attestations Litecoin et Ethereum, les réseaux `testnet` et `signet` ; la
  détection d'une réorganisation sous le point de contrôle.
- **L'heure exacte de Bitcoin** : seule l'antériorité au bloc est prouvée
  (10.6).
- **La preuve Merkle-Patricia d'un seul reçu** à la place de tous les reçus du
  bloc, et **le certificat réduit aux precommits** (R3 NV1).
- **Les faits d'état du registre** : `getPeriod`, `lookup`,
  `recorderByPubKey`, appartenance au `CuratorSet`, non-révocation d'une clé
  d'enregistreur, dernière période d'un journal (R3 F41) ; l'absence d'un
  événement.
- **Le code des contrats** aux adresses de l'ancre (R3 NV7) et **la provenance
  du jeu de validateurs** (R3 NV5).
- **L'identifiant EVM de la chaîne** et le lien entre `transaction_hash` et le
  reçu.
- **La légitimité des approbateurs** d'un événement (contrôle 7) à l'instant de
  la décision : le registre la constate pour la clôture (R3 F36) mais pas pour
  chaque décision.
- **Le binaire** lui-même (phase 2) et le lieu de publication de la clé
  publique minisign.

## Annexe A — Vecteurs CT-6

### A.1 Principes

**EX-A.1** Les vecteurs sont sous `spec/vecteurs/ct-6/`, produits par
`scripts/vecteurs/generer-ct6.mjs` (`npm run vecteurs:ct6`) et rejoués à
l'identique : clés, horodatages, numéros de série et nonces fixes. Seul
`registre/capture/` est une entrée capturée une fois sur le réseau de
développement (A.5) ; le générateur la lit et ne la réécrit jamais. Le
générateur efface et réécrit tout le reste de `spec/vecteurs/ct-6/`, sauf
`registre/capture/`, les clés `rfc3161/cles/*.cle.pem` (A.3) et
`confrontation/` (A.8).

**EX-A.2** Données de base : le journal `journal-sinistres` des vecteurs de
CT-1, ses trois manifestes
(`spec/vecteurs/ct-1/manifestes/periode-{1,2,3}.json`, `periodHash` respectifs
`0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914`,
`0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19`,
`0x5852e3c7f403875b9b634f5e5d7074ea197fc34ecf80e092b9686d8c2dc80594`), et le
dossier `spec/vecteurs/ct-1/dossiers/valide-seq-7/` (période 1). Les vecteurs
de CT-1 ne changent pas.

**EX-A.3** Chaque dossier de `dossiers/` porte un `attendu.json` (étranger au
dossier, ignoré par le vérificateur, CT-1 §11.1) :

| Clé | Contenu |
|---|---|
| `valid` | booléen |
| `target` | identifiant visé (`T-2`, `O-5`, `R-7`, `N-3`…) ou `null` |
| `failed_checks` | liste exacte des vérifications en échec, dans l'ordre D, E, C, M, P, A (CT-1 §11.4), puis T, O, R, N par numéro |
| `control_statuses` | `{ "1": …, …, "8": … }`, valeurs `reussi`, `echoue`, `non_execute` |
| `not_executed` | liste `{id, reason}` des vérifications non exécutées, `reason` étant une raison de la table 6.2 (`prerequis_en_echec` pour une dépendance d'une vérification en échec) |
| `warnings` | liste exacte des avertissements (`AV-…`), dans l'ordre de EX-6.15 |
| `anchors` | chemin du fichier d'ancres, relatif au répertoire du dossier, ou `null` (vérification sans ancres) |
| `bitcoin_headers` | chemin du fichier d'en-têtes, relatif, ou `null` |
| `exit_code` | code de retour attendu (section 8) |
| `statement` | `{fr, en}` : l'énoncé attendu dans les deux langues, construit selon la section 6.5 (EX-6.8, EX-6.9) ; `null` pour le code 2 |
| `bound` | `{fr, en}` : la borne attendue (EX-6.12), ou `null` |
| `description` | texte |

### A.2 Disposition

```text
spec/vecteurs/ct-6/
  INDEX.md                      généré : chaque cas, son attendu, la procédure de capture
  ancres/                       fichiers d'ancres de test (A.6)
  rfc3161/
    cles/                       entrée : clés RSA et certificats de test (A.3)
    jetons/                     jetons DER et leur description (A.3)
    crl/                        CRL de test (A.3)
    attendu.json
  ots/
    entetes/                    chaînes d'en-têtes synthétiques (A.4)
    preuves/                    fichiers .ots (A.4)
    attendu.json
  registre/
    capture/                    entrée : réponses JSON-RPC brutes (A.5)
    periode-1/                  registre.json, certificat-commit.json, validateurs.json dérivés de la capture
    periode-2/                  idem pour la période 2 (sert à R-9)
    attendu.json                hachages BFT, racines des reçus, événements décodés
  dossiers/                     dossiers complets (A.7)
  confrontation/                programmes et sorties des implémentations tierces (A.8)
```

### A.3 `rfc3161/`

**EX-A.4** `cles/` (entrée, publique, pour les tests seulement) :
`ac-test.cle.pem` et `ac-test.pem` (AC racine RSA 3072, sujet `C=CH,
O=NOORTRACE vecteurs, CN=AC de test CT-6`, `basicConstraints` critique
`CA:TRUE`, `keyUsage` critique `keyCertSign, cRLSign`, validité
2026-01-01T00:00:00Z à 2036-01-01T00:00:00Z) ; `tsa-test.cle.pem` et
`tsa-test.pem` (unité RSA 3072, `CN=TSA de test CT-6`, émise par l'AC,
`keyUsage` critique `digitalSignature`, `extKeyUsage` critique `timeStamping`,
validité 2026-06-01T00:00:00Z à 2027-06-01T00:00:00Z) ; `tsa-expiree.pem`
(même clé, validité 2026-01-01T00:00:00Z à 2026-06-30T23:59:59Z) ;
`tsa-eku-non-critique.pem` (même clé, `extKeyUsage` non critique) ;
`tsa-critique-faux.pem` (même clé, extension `subjectKeyIdentifier` dont
`critical` est encodé à `FALSE`, valeur `DEFAULT` que EX-9.21 refuse) ;
`tsa-cn-utf8-invalide.pem` (même clé, `CN` en `UTF8String` des octets `ff fe`,
UTF-8 invalide, EX-9.4) ; `tsa-sans-cn.pem` (même clé, sujet `C=CH,
O=NOORTRACE vecteurs, unité sans CN`, sans `commonName`). Les clés sont
produites une fois et conservées, pour que les vecteurs ne dépendent d'aucune
génération de clé RSA. Seuls les fichiers `*.cle.pem` sont des entrées ; les
certificats sont réécrits par le générateur.

**EX-A.5** `jetons/` : un jeton par période, `periode-{1,2,3}.der`, sur le
`periodHash` de la période, `genTime` = `period_end` + 5 s (`20261105100005Z`,
`20261105110005Z`, `20261105120005Z`), `serialNumber` = 1, 2, 3, `accuracy` =
1 s, `policy` = `1.3.6.1.4.1.99999.1.1` (OID d'essai de R1 F6.08), `nonce` = 8
premiers octets de
SHA-256(UTF-8(`noortrace/vecteurs/v0/ct-6/nonce-tsa/periode-N`)), `tsa` =
sujet de l'unité, `certificates` = [`tsa-test.pem`], `signingCertificateV2` en
SHA-256, signature `sha256WithRSAEncryption` ; puis les variantes, chacune sur
le `periodHash` de la période 1 :

| Fichier | Altération | Vérification visée |
|---|---|---|
| `t1-octet-en-trop.der` | un octet `00` après le `ContentInfo` | T-1 |
| `t3-message-digest.der` | `genTime` avancé d'une seconde dans `TSTInfo`, `signedAttrs` re-signés, `message-digest` inchangé | T-3 |
| `t4-ess-autre-certificat.der` | `certHash` de `ESSCertIDv2` = SHA-256 de `ac-test.pem`, re-signé | T-4 |
| `t5-sha1.der` | `digestAlgorithm` et signature en SHA-1 | T-5 |
| `t6-signature.der` | dernier octet de la signature inversé | T-6 |
| `t7-tsa-expiree.der` | signé par la même clé, `certificates` = [`tsa-expiree.pem`] | T-7 |
| `t8-eku-non-critique.der` | `certificates` = [`tsa-eku-non-critique.pem`] | T-8 |
| `t9-extension-critique.der` | extension critique d'OID `1.3.6.1.4.1.99999.2` dans `TSTInfo`, re-signé | T-9 |
| `t1-default-explicite.der` | `certificates` = [`tsa-critique-faux.pem`], signé par la même clé | T-1 (EX-9.21) |
| `t1-cn-utf8-invalide.der` | `certificates` = [`tsa-cn-utf8-invalide.pem`], champ `tsa` absent | T-1 (EX-9.4) |
| `periode-1-unite-sans-cn.der` | `certificates` = [`tsa-sans-cn.pem`], `tsa` = son sujet | aucune : jeton valide, `tsu_subject_cn` nul (EX-9.19) |

T-2 se teste avec `periode-2.der` dans un dossier de la période 1 ; T-10 avec
`periode-1.der` et l'ancre `ancres-tsa-revoquee.json` (certificat du chemin
révoqué) ou `ancres-unite-epinglee-revoquee.json` (certificat de l'autorité,
une unité épinglée, révoqué par une CRL du fichier d'ancres, EX-9.16) ; le
choix de l'autorité de T-7 avec `ancres-deux-autorites.json` ; T-11 réussie avec
`periode-1.der` et l'ancre `ancres-qualification-declaree.json` (avec
`ancres-test.json`, T-11 est `non_execute`, `ancre_absente`). `crl/` :
`crl-vide.pem` (émise par l'AC, `thisUpdate` 2026-11-06T00:00:00Z) et
`crl-tsa-revoquee.pem` (même instant, `tsa-test.pem` révoqué le
2026-11-05T12:00:00Z pour `keyCompromise`). `attendu.json` donne, par jeton,
`period_hash`, `gen_time`, `serial_number`, les statuts attendus de T-1 à T-11
avec `ancres/ancres-test.json`, et le résultat attendu de `openssl ts -verify
-digest <periodHash> -in <jeton> -token_in -CAfile ac-test.pem
-attime <genTime>`. Attendus établis par R1 : `Verification: OK` pour les
trois jetons valides et `message imprint mismatch` pour un jeton confronté
au `periodHash` d'une autre période (R1 F6.08) ; `certificate has expired`
pour T-7 (R1 F5.14) ; refus d'un `extKeyUsage` non critique pour T-8, selon
le code lu (R1 F5.12). Résultats relevés par la confrontation (A.8, OpenSSL
3.0.13) et inscrits dans `attendu.json` : `Verification: OK` pour `t1`
(l'octet qui suit le `ContentInfo` est ignoré ; `openssl asn1parse` relève
« Error in encoding »), `t5` (OpenSSL n'applique pas la table de EX-9.11),
`t9` (OpenSSL ne refuse pas une extension critique inconnue de `TSTInfo`),
`t1-default-explicite` et `periode-1-unite-sans-cn` ; `digest failure` pour
`t3` ; `ess cert id not found` pour `t4` ; `invalid padding` et `signature
failure` pour `t6` ; `invalid utf8string` pour `t1-cn-utf8-invalide`, qu'OpenSSL
ne lit pas.

### A.4 `ots/`

**EX-A.6** `entetes/chaine.json` : chaîne synthétique `regtest` de hauteur 990
à 1020, `nVersion` = `0x20000000`, `nBits` = `0x207fffff`, `nTime(990)` =
1793880000 (2026-11-05T12:00:00Z, après la fin des trois périodes) puis +600 s
par bloc, `prev(990)` = 32
octets nuls, `nNonce` = le plus petit entier qui satisfait la preuve de
travail à la cible regtest, `racine(i)` = résultat des opérations de la preuve
attestée en `i` pour 1001, 1002 et 1003 (périodes 1, 2, 3), et
`dSHA(UTF-8("noortrace/vecteurs/v0/ct-6/bitcoin/racine/<i>"))` pour les autres.
Point de contrôle des ancres de test : hauteur 1000, profondeur minimale 6.
Variantes : `chaine-sans-travail.json` (le `nNonce` de 1010 remplacé par une
valeur qui ne satisfait pas la cible, chaînage refait au-dessus) ;
`chaine-courte.json` (990 à 1003) ; `chaine-depuis-1001.json` (les en-têtes
1001 à 1020 de `chaine.json`, sans la hauteur 1000 du point de contrôle :
O-5 `non_execute`, `ancre_absente`, EX-10.9 règle 3).

**EX-A.7** `preuves/periode-{1,2,3}.ots` : empreinte = `periodHash` ;
opérations `f0` (16 octets =
SHA-256(UTF-8(`noortrace/vecteurs/v0/ct-6/ots/nonce/periode-N`)) tronqué à
16), `08`, puis un chemin `f0`/`f1`/`08` qui imite l'agrégation d'un
calendrier et la transaction Bitcoin, et une attestation Bitcoin à la hauteur
1000 + N ; seules `f0`, `f1`, `08` sont employées. Variantes, sur la période 1
: `o1-octet-en-trop.ots` (un octet après l'arbre, O-1),
`o3-resultat-trop-long.ots` (branche supplémentaire `f0` d'un argument de 4096
octets, O-3), `o4-mauvaise-hauteur.ots` (attestation à 1002, O-4),
`o7-en-attente.ots` (seulement une attestation en attente d'URI
`https://alice.btc.calendar.opentimestamps.org`, O-7), `deux-attestations.ots`
(attestations à 1001 et 1002, AV-O-1), `attente-uri-vide.ots` (à côté de la
branche attestée à 1001, une attestation en attente d'URI vide, que la
bibliothèque de référence admet : O-1 réussie, AV-O-2) et
`branche-hors-profil.ots` (à côté de la branche attestée à 1001, une branche
`03` (RIPEMD-160) finie par une attestation Bitcoin à 1003, non exécutée :
O-3 réussie, AV-O-2, EX-10.7). La variante O-2 est `periode-2.ots`
dans un dossier de la période 1 ; O-5 et O-6 se testent par les fichiers
d'en-têtes.

### A.5 `registre/capture/` : capture unique

**EX-A.8** Procédure, exécutée une fois sur le réseau de développement (`bash
chain/scripts/dev-net.sh start`, contrats de `deployments/noorcore.json`), par
`scripts/vecteurs/capturer-ct6.mjs`, puis `dev-net.sh stop` :

1. amorcer l'organisation `assureur-demo` (`org_id` de CT-1 §13) avec un
   `CuratorSet` des comptes Hardhat 1 à 3 au seuil de 2 ;
2. inscrire `rec-test-01` sous la clé de chaîne `0xaa2a59656361352e96ef2eed355316ef8b29dab7`,
   `rec-test-02` sous `0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49`, et une clé
   étrangère au dossier, `rec-test-03` (graine
   SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-enregistreur/rec-test-03`)), clé
   publique `0x7fcebb9e8efd62d13a17c830ad33739c1de7fe9f1458701cb739ae15e9e62cd6`),
   sous `0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22`, pour le journal
   `journal-sinistres` ; les clés privées de chaîne sont
   SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-0N`)) ;
3. ancrer la période 1 puis la période 2 (`anchor`, émetteur : la clé de chaîne
   de `rec-test-02`, qui signe les deux manifestes) ;
4. soumettre la période 1 puis la période 2 (`submitPeriod`, approbateurs 1 et
   2) ; les transactions sont relayées par le compte Hardhat 0 ;
5. pour chaque transaction, dès son reçu : `eth_getBlockByNumber(h, false)`,
   `eth_getTransactionReceipt` de chaque transaction du bloc,
   `noor_getCommitCertificate(h)` (EX-13.8), écrits tels que reçus dans
   `bloc-<h>.json`, `recu-<hash>.json`, `certificat-<h>.json` ; plus
   `validators.json` (copie de `chain/runtime/validators.json`) et
   `capture.json` (date, commit de noorchain-core et correctif appliqué,
   `chainId`, adresses des contrats, transactions avec leur rôle et leur bloc).

La capture est une entrée : on ne la recapture que si elle doit changer.
Recapturer exige une chaîne où ni ces empreintes ni ces `periodHash` ne sont
déjà enregistrés (`AttestationRegistry` refuse une empreinte déjà ancrée,
`PeriodRegistry` un `periodHash` déjà connu de l'organisation) : un réseau
neuf dans un répertoire d'exécution vide (`NOORTRACE_RUNTIME_DIR`, réseau
principal de développement arrêté, mêmes ports), avec déploiement des
contrats, `deployments/noorcore.json` sauvegardé avant et restauré après.

**EX-A.9** Les horodatages des blocs capturés sont ceux de la capture
(octobre 2026), antérieurs aux dates fictives des manifestes de CT-1 (novembre
2026). Aucune vérification ne compare l'heure déclarée d'un bloc à
`generated_at` (EX-11.18) : cette incohérence des vecteurs est sans effet et
documentée dans `INDEX.md`.

### A.6 `ancres/`

**EX-A.10**

| Fichier | Contenu |
|---|---|
| `ancres-test.json` | autorité `ac-test.pem` (politique d'essai admise, `qualified` = `null` : aucun statut qualifié déclaré), `crl-vide.pem` ; `bitcoin` `regtest`, point de contrôle 1000 et son hachage, profondeur 6 ; `registry` : `chain_id`, adresses et jeu de validateurs de `capture.json` et `validators.json` ; `recorders` : `rec-test-01` et `rec-test-02` avec leurs clés de chaîne |
| `ancres-qualification-declaree.json` | idem, `qualified` = `{framework: "eidas", valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "déclaration de test, sans valeur"}` |
| `ancres-tsa-revoquee.json` | idem, `crl-tsa-revoquee.pem` à la place de `crl-vide.pem` |
| `ancres-autre-chaine.json` | idem, `chain_id` = `noortrace-9999-test` |
| `ancres-autre-registre.json` | idem, `period_registry` = adresse d'`AttestationRegistry` |
| `ancres-cle-enregistreur-autre.json` | idem, `public_key` de `rec-test-01` remplacée par celle de `rec-test-02` |
| `ancres-cle-chaine-autre.json` | idem, `chain_key` de `rec-test-02` remplacée par celle de `rec-test-01` |
| `ancres-sans-enregistreurs.json` | idem, `recorders` vide : N-3 et N-4 ne figurent pas, les clés ne sont confirmées que par le registre (provenance `registre`) |
| `ancres-enregistreur-01-seul.json` | idem, `recorders` réduit à `rec-test-01` (provenance `mixte` avec les parties de `valide-provenance-mixte`) |
| `ancres-deux-jeux.json` | idem, `validator_sets` scindé en deux jeux de mêmes validateurs : hauteurs 1 à 16660 (bloc de l'ancre de la période 1), puis 16661 et suivantes |
| `ancres-unite-epinglee-revoquee.json` | idem, `tsa_authorities` réduit à l'unité `tsa-test.pem` épinglée (nom « Unité TSA épinglée de test CT-6 »), `crl-tsa-revoquee.pem` |
| `ancres-deux-autorites.json` | idem, `tsa_authorities` = l'unité `tsa-test.pem` épinglée (statut qualifié déclaré comme dans `ancres-qualification-declaree.json`), puis `ac-test.pem` ; `crl-vide.pem` |

### A.7 `dossiers/`

**EX-A.11** `valide-seq-7-complet/` est le dossier `valide-seq-7` de CT-1, ses
sept premières parties inchangées, complété de `jeton-rfc3161.der`
(`periode-1.der`), `preuve.ots` (`periode-1.ots`), `registre.json`,
`certificat-commit.json` et `validateurs.json` de `registre/periode-1/`
(entrées : inscriptions de `rec-test-01` et `rec-test-02`, ancre et clôture de
la période 1), `dossier.json` recalculé (les douze parties présentes,
`generated_at` inchangé), écrit comme CT-1 §11.1 l'indique
(`JSON.stringify(objet, null, 2)` suivi d'un saut de ligne). Chaque autre
dossier en est une copie dont une seule chose change, sauf les deux dossiers
de décision, construits à part (dernières lignes de la table) :

| Dossier | Changement | `failed_checks` | Remarque |
|---|---|---|---|
| `valide-seq-7-complet/` | — | aucun | ancres `ancres-test.json`, en-têtes `chaine.json` ; les huit contrôles réussissent ; T-11 `non_execute` (`ancre_absente`), l'énoncé ne dit pas « qualifié » ; avertissements : `AV-O-3` |
| `valide-seq-7-complet-sans-ancres/` | aucun ; vérifié sans ancres, avec `chaine.json` | aucun | contrôles 4, 5, 8 `non_execute` (`ancre_absente`) ; N-3 et N-4 absentes du rapport (EX-5.6) ; aucun avertissement |
| `valide-seq-7-complet-sans-entetes/` | aucun ; vérifié avec `ancres-test.json`, sans fichier d'en-têtes | aucun | contrôle 5 `non_execute` (`partie_absente`, EX-4.5) |
| `valide-t11-qualification-declaree/` | ancres `ancres-qualification-declaree.json` | aucun | T-11 réussie ; l'énoncé dit « horodatage qualifié eIDAS selon le réviseur (déclaration de test, sans valeur) » |
| `invalide-t1-octet-en-trop/` | jeton `t1-octet-en-trop.der` | T-1 | |
| `invalide-t2-jeton-autre-manifeste/` | jeton `periode-2.der` | T-2 | |
| `invalide-t3-message-digest/` | jeton `t3-message-digest.der` | T-3 | |
| `invalide-t4-ess-autre-certificat/` | jeton `t4-ess-autre-certificat.der` | T-4 | |
| `invalide-t5-sha1/` | jeton `t5-sha1.der` | T-5 | |
| `invalide-t6-signature/` | jeton `t6-signature.der` | T-6 | |
| `invalide-t7-tsa-expiree/` | jeton `t7-tsa-expiree.der` | T-7 | |
| `invalide-t8-eku-non-critique/` | jeton `t8-eku-non-critique.der` | T-8 | |
| `invalide-t9-extension-critique/` | jeton `t9-extension-critique.der` | T-9 | |
| `invalide-t10-tsa-revoquee/` | ancres `ancres-tsa-revoquee.json` | T-10 | |
| `invalide-o1-octet-en-trop/` | preuve `o1-octet-en-trop.ots` | O-1 | |
| `invalide-o2-preuve-autre-manifeste/` | preuve `periode-2.ots` | O-2 | |
| `invalide-o3-resultat-trop-long/` | preuve `o3-resultat-trop-long.ots` | O-3 | |
| `invalide-o4-mauvaise-hauteur/` | preuve `o4-mauvaise-hauteur.ots` | O-4 | |
| `invalide-o5-chaine-sans-travail/` | en-têtes `chaine-sans-travail.json` | O-5 | |
| `non-execute-o6-profondeur/` | en-têtes `chaine-courte.json` | aucun | contrôle 5 `non_execute` (`ancre_absente`) ; dossier valide |
| `non-execute-o7-en-attente/` | preuve `o7-en-attente.ots` | aucun | contrôle 5 `non_execute` (`partie_absente`) ; dossier valide ; `AV-O-2` |
| `valide-deux-attestations/` | preuve `deux-attestations.ots` | aucun | `AV-O-1` |
| `invalide-r1-sans-ancre/` | entrée `ancre` retirée de `registre.json` | R-1 | |
| `invalide-r2-jeu-substitue/` | certificats re-signés (mêmes corps, même `blockHash`) par quatre validateurs `v1` à `v4` de clés privées SHA-256(UTF-8(`noortrace/vecteurs/v0/ct-6/validateur-substitue/vN`)), `validateurs.json` déclarant ce jeu | R-2 | R-3 réussie, R-5 et N-4 `non_execute` (`prerequis_en_echec`, EX-12.5) |
| `invalide-r3-validateurs-declares/` | clé de `v4` remplacée, dans `validateurs.json`, par celle du `v1` substitué | R-3 | |
| `invalide-r4-autre-chaine/` | ancres `ancres-autre-chaine.json` | R-4 | |
| `invalide-r5-quorum/` | une ligne de precommit retirée du certificat de la clôture, qui en avait le quorum exact | R-5 | si la capture donne plus que le quorum, retirer jusqu'à passer sous le quorum |
| `invalide-r6-entete-modifie/` | `timestamp` + 1 dans `block` de l'entrée `cloture` | R-6 | |
| `invalide-r7-recu-falsifie/` | `topics[2]` (`periodHash`) du journal de la clôture remplacé par `0x11…11` | R-7 | |
| `invalide-r8-autre-contrat/` | ancres `ancres-autre-registre.json` | R-8 | |
| `invalide-r9-cloture-autre-periode/` | entrées `cloture` et `ancre` et leurs certificats pris dans `registre/periode-2/` | R-9 | |
| `invalide-r10-inscription-cle-inconnue/` | entrée `inscription` de `rec-test-03` et certificat de son bloc ajoutés | R-10 | |
| `invalide-n3-cle-enregistreur/` | ancres `ancres-cle-enregistreur-autre.json` | N-3 | contrôle 6 `echoue` |
| `invalide-n4-cle-chaine/` | ancres `ancres-cle-chaine-autre.json` | N-4 | contrôle 8 `echoue` |
| `invalide-t1-default-explicite/` | jeton `t1-default-explicite.der` | T-1 | valeur `DEFAULT` encodée dans le certificat de l'unité (EX-9.21) |
| `invalide-t1-cn-utf8-invalide/` | jeton `t1-cn-utf8-invalide.der` | T-1 | `UTF8String` invalide dans le sujet de l'unité (EX-9.4) |
| `invalide-t10-unite-epinglee-revoquee/` | ancres `ancres-unite-epinglee-revoquee.json` | T-10 | certificat de l'autorité (l'unité épinglée) révoqué par la CRL du fichier d'ancres (EX-9.16) |
| `valide-t7-deux-autorites/` | ancres `ancres-deux-autorites.json` | aucun | T-7 retient la première autorité, l'unité épinglée, par l'identité (EX-9.13) ; T-11 réussie ; l'énoncé nomme « Unité TSA épinglée de test CT-6 » |
| `valide-unite-sans-cn/` | jeton `periode-1-unite-sans-cn.der` | aucun | `tsu_subject_cn` nul ; l'énoncé nomme l'unité par le SHA-256 de son certificat (EX-9.20) |
| `valide-attente-uri-vide/` | preuve `attente-uri-vide.ots` | aucun | `AV-O-2` |
| `valide-o3-branche-hors-profil/` | preuve `branche-hors-profil.ots` | aucun | O-3 réussie ; `AV-O-2` (EX-10.7) |
| `non-execute-o5-point-de-controle-hors-entetes/` | en-têtes `chaine-depuis-1001.json` | aucun | O-5 `non_execute` (`ancre_absente`, EX-10.9), contrôle 5 `non_execute` ; pas d'`AV-O-3` ; dossier valide |
| `invalide-p1-manifeste-membre-en-trop/` | membre `extra` ajouté à `manifeste.json`, `dossier.json` réindexé | P-1, P-5 | T-2, O-2, R-9 et R-10 `non_execute` (`prerequis_en_echec`), les autres T-, O- et R- exécutées (EX-5.4) ; contrôles 4, 5 et 8 `non_execute` |
| `valide-sans-inscription/` | parties du registre de `registre/variantes/valide-sans-inscription/` (inscriptions retirées) | aucun | R-10 `non_execute` (`partie_absente`) ; `AV-R-1` |
| `valide-ligne-non-canonique/` | parties du registre de `registre/variantes/valide-ligne-non-canonique/` (membre `Domain` dans une ligne de precommit, que le décodeur du nœud accepte) | aucun | `AV-R-2` |
| `valide-provenance-registre/` | ancres `ancres-sans-enregistreurs.json` | aucun | N-3 et N-4 absentes ; les deux clés confirmées par R-10, provenance `registre` (EX-6.8) |
| `valide-provenance-mixte/` | parties du registre de `registre/variantes/valide-provenance-mixte/` (inscription de `rec-test-01` retirée), ancres `ancres-enregistreur-01-seul.json` | aucun | `rec-test-01` confirmée par N-3, `rec-test-02` par R-10 : provenance `mixte`, écrite clé par clé (EX-6.8) ; N-4 absente |
| `valide-deux-jeux-validateurs/` | ancres `ancres-deux-jeux.json` | aucun | proposition de l'énoncé en deux groupes de blocs (EX-11.22) |
| `valide-decision-refusee/` | construit à part par `scripts/vecteurs/ct6/decisions.mjs` : dossier de la décision (seq 6) d'une variante du journal de CT-1 où la décision du ticket `apr-2201` est un refus signé par les comptes Hardhat 1 et 2 ; cinq parties réservées absentes ; vérifié sans ancres | aucun | contrôles 4, 5 et 8 `non_execute` (`hors_perimetre_version`) ; F3 « porte un refus signé par » (EX-6.8) |
| `valide-decision-expiree/` | idem, décision `expire` sans approbateur ni signature | aucun | idem ; F3 « porte une demande d'approbation expirée sans signature » ; `facts.approval.approvers` vide |

Sauf mention, l'ancre est `ancres-test.json` et les en-têtes `chaine.json` ;
tout dossier où O-5 est exécutée porte `AV-O-3` (réseau `regtest`), dans
l'ordre de EX-6.15. Les vérifications qui dépendent d'une
vérification en échec sont listées dans `not_executed` avec la raison
`prerequis_en_echec`. Les 40 dossiers de CT-1 (`spec/vecteurs/ct-1/dossiers/`)
gardent leur code de retour et leur liste de contrôles en échec sans ancres,
comme la CI les vérifie ; avec `ancres-test.json`, leur liste ne change pas
non plus, ce que les tests vérifient. Leurs cinq parties réservées sont
absentes. Leurs `cles.json` ne portent sous `rec-test-01` et `rec-test-02`
que les clés de CT-1 §13, qui sont celles d'`ancres-test.json`, sauf
`invalide-cles-key-id-double`, dont la seconde entrée `rec-test-01` porte une
autre clé. Dans ce dossier comme dans `invalide-cles-autre-journal`, E-8
échoue, et N-3 est non exécutée, raison `prerequis_en_echec` (EX-12.4) : elle
s'ajoute à `blocking_unexecuted`, non à `failed_checks`. Ailleurs, N-3 est
réussie, ou absente du rapport (`invalide-nombre-non-entier`,
`invalide-partie-nulle`).

### A.8 Confrontation par des implémentations tierces

**EX-A.12** `confrontation/` porte les programmes et leurs sorties, publiées
(`sorties/*.txt`), qui recalculent les vecteurs sans le code du dépôt ; chaque
sous-répertoire a son `LISEZMOI.md` (commande, versions, limites de l'outil) :

| Famille | Programme et sortie | Outil tiers | Ce qu'il confirme |
|---|---|---|---|
| `rfc3161/` | `confrontation/rfc3161/confronter_rfc3161.py`, `sorties/rfc3161.txt` | OpenSSL 3.0.13 : `ts -verify … -token_in -attime <genTime>`, `ts -reply -text`, `cms -verify` et `-cmsout -print`, `asn1parse`, `x509`, `crl`, `verify -partial_chain`, `verify -crl_check` | SHA-256 des clés, certificats, CRL et jetons ; champs de `TSTInfo` ; statut de T-1 à T-10 cas par cas (T-5 et T-11 hors outil) ; faits de EX-9.19 ; résultats d'`openssl ts -verify` inscrits dans `attendu.json` (A.3) |
| `ots/` | `confrontation/ots/confronter_ots.py`, `sorties/ots.txt` | `python-opentimestamps` 0.4.5 (paquet PyPI `opentimestamps`, LGPL-3.0 ou ultérieure, R2-F59) et `python-bitcoinlib` 0.12.2, installés par `pip` dans un environnement virtuel et employés hors ligne (`DetachedTimestampFile.deserialize`, `verify_against_blockheader`, `CheckProofOfWork`) | lecture des `.ots`, résultat des opérations égal aux octets 36 à 67 des en-têtes ; rejet de `o1` et `o3` (R2-F67) ; statut de O-1 à O-7, du contrôle 5, avertissements et faits, cas par cas |
| `registre/` | `confrontation/registre/main.go`, `sorties/registre.txt` | go-ethereum v1.17.0 (version que noorchain-core épingle) : `types.DeriveSha`, `abi` ; `node.BFTBlockHash` et `consensus.VerifyEnvelope` de noorcore, dont le module est employé en lecture seule, sur une copie locale de noorchain-core | hachages BFT, racines des reçus, journaux décodés, enveloppes des certificats ; statut de R-1 à R-10 et N-4 de chaque jeu de parties et de chaque variante |
| certificats | `sorties/registre-certificats.txt` | `scripts/verify/certificat-commit.mjs --chaine noortrace-2124-dev` | chaque certificat capturé, contre `validators.json` |

Une limite d'un outil (une vérification qu'il ne fait pas, ou une lecture
plus permissive que CT-6) n'est pas une discordance : elle est décrite dans
le `LISEZMOI.md` de la famille. `test/confrontation.test.js` exige que les
sorties publiées portent sur les vecteurs du dépôt (SHA-256 des fichiers,
cas, statuts du registre, aucune discordance) ; la CI rejoue les programmes
`rfc3161` et `ots`.

La concordance des sorties tierces avec `attendu.json` est la condition de
publication des vecteurs, comme pour CT-1 §13.

## Annexe B — Sources des faits externes

Les renvois R1 à R4 du texte désignent des notes de recherche internes du lot
CT-6, non publiées : R1 (horodatage RFC 3161 et listes de confiance), R2
(OpenTimestamps et Bitcoin), R3 (registre et contrôle 8), R4 (construction et
sûreté). Cette annexe donne, pour chaque renvoi, l'objet du fait en quelques
mots et les sources primaires publiques que la note a consultées, à la date
indiquée ; ces sources font foi, pas la note. Un fait marqué « non vérifié »
dans le texte le reste. Un fait tiré du code de noorcore, dépôt privé, n'est
pas recoupable publiquement.

Conventions :

- un renvoi à un fait s'écrit comme dans le texte : « R1 F3.16 », « R2-F37 »,
  « R3 NV7 » (point non vérifié de la note) ; les listes et les plages du
  texte (« R2-F37 à R2-F39 ») sont développées, un fait par ligne ;
- un renvoi à la note entière (« digest R2 », « capture R3 »), à une
  conséquence de la note (« R3, conséquence 6 ») ou à un point non vérifié
  numéroté (« point non vérifié 5 du digest R2 ») s'écrit « Rn (section x.y) »,
  x.y étant la section de cette spécification où il figure ; la colonne
  « Objet » nomme la conséquence ou le point, et les sources sont celles de la
  note qui concernent ce passage ;
- les URL sont recopiées de la note, une par source, séparées par « ; » ; une
  adresse que la note n'écrit qu'en abrégé (« …/ ») n'est pas complétée, et
  la ligne le dit ;
- « présent dépôt » désigne un fichier de ce dépôt public, que la note cite par
  son chemin sans URL : source publique, recoupable dans ce dépôt ;
- « essai de la note » et « expérience de la note » désignent une manipulation
  faite par la note (OpenSSL, Go, réseau de développement de noorcore) dont
  les sorties ne sont pas publiées ;
- « aucune URL dans la note » : source publique (code de Go, de go-ethereum)
  que la note désigne par sa version sans en donner l'adresse ; quand la ligne
  ne cite aucune autre source publique, elle ajoute « aucune source primaire
  publique dans la note ; fait non recoupable ».

### B.1 R1 — Horodatage RFC 3161 et listes de confiance

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R1 F1.01 | structure de `TimeStampResp` et de `PKIStatusInfo` | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.02 | statut de la réponse et présence du jeton | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.04 | `TimeStampToken` = `ContentInfo` ; `id-ct-TSTInfo` | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.05 | signature unique de la TSA ; attribut `SigningCertificate` | https://www.rfc-editor.org/rfc/rfc3161.txt ; https://www.rfc-editor.org/rfc/rfc5816.txt | 2026-10-22 |
| R1 F1.06 | structure de `TSTInfo` | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.10 | `serialNumber`, entiers jusqu'à 160 bits | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.11 | `genTime` : UTC, fractions de seconde, forme DER | https://www.rfc-editor.org/rfc/rfc3161.txt ; https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf | 2026-10-22 |
| R1 F1.12 | `accuracy` et borne de l'instant de création | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.14 | `nonce` égal à celui de la requête | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.15 | champ `tsa`, simple indice | https://www.rfc-editor.org/rfc/rfc3161.txt ; https://www.rfc-editor.org/rfc/rfc5816.txt | 2026-10-22 |
| R1 F1.16 | règles de vérification par le demandeur | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.17 | la TSA n'examine pas l'empreinte | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.18 | EKU `id-kp-timeStamping` unique et critique | https://www.rfc-editor.org/rfc/rfc3161.txt ; https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F1.19 | `certReq` et champ `certificates` | https://www.rfc-editor.org/rfc/rfc3161.txt ; https://www.rfc-editor.org/rfc/rfc5816.txt | 2026-10-22 |
| R1 F1.21 | révocation du certificat de la TSA et validité des jetons | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.23 | deux jetons sur une même donnée partagent l'empreinte | https://www.rfc-editor.org/rfc/rfc3161.txt | 2026-10-22 |
| R1 F1.26 | RFC 5816 : `SigningCertificateV2` | https://www.rfc-editor.org/rfc/rfc5816.txt | 2026-10-22 |
| R1 F1.27 | RFC 5035 : `ESSCertIDv2`, `id-aa-signingCertificateV2` | https://www.rfc-editor.org/rfc/rfc5035.txt | 2026-10-22 |
| R1 F1.28 | errata 2364 de RFC 5035 (`certHash`) | https://www.rfc-editor.org/rfc/rfc5035.txt ; https://www.rfc-editor.org/api/v1/errata.json | 2026-10-22 |
| R1 F1.29 | RFC 2634 : `ESSCertID`, `id-aa-signingCertificate` | https://www.rfc-editor.org/rfc/rfc2634.txt | 2026-10-22 |
| R1 F2.01 | `ContentInfo` ; `id-signedData` | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.02 | `SignedData` et sa version | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.04 | champ `crls` ; réponse OCSP (`id-ri-ocsp-response`) | https://www.rfc-editor.org/rfc/rfc5652.txt ; https://www.rfc-editor.org/rfc/rfc5940.txt | 2026-10-22 |
| R1 F2.06 | `SignerInfo` ; deux formes de `sid` | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.07 | `signedAttrs` : présence, DER, attributs requis | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.08 | calcul de la signature sur `signedAttrs` | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.09 | recalcul de l'empreinte ; attribut content-type | https://www.rfc-editor.org/rfc/rfc5652.txt ; https://www.rfc-editor.org/rfc/rfc8933.txt | 2026-10-22 |
| R1 F2.10 | attribut content-type (OID) | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.11 | attribut message-digest (OID) | https://www.rfc-editor.org/rfc/rfc5652.txt | 2026-10-22 |
| R1 F2.12 | DER : tri des SET OF, valeurs DEFAULT non encodées | https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf | 2026-10-22 |
| R1 F2.14 | `rsaEncryption` comme algorithme de signature CMS | https://www.rfc-editor.org/rfc/rfc3370.txt | 2026-10-22 |
| R1 F2.15 | identifiants SHA-2 : paramètres absents ou NULL | https://www.rfc-editor.org/rfc/rfc5754.txt ; RFC 4056 : URL abrégée dans la note | 2026-10-22 |
| R1 F2.17 | essai : signature sur `signedAttrs` avec l'étiquette 0x31 | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R1 F3.03 | EN 319 422 : exigences sur le jeton | https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf | 2026-10-22 |
| R1 F3.06 | TS 119 312 : algorithmes exigés des vérificateurs de jetons | https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf | 2026-10-22 |
| R1 F3.07 | TS 119 312 : fin des clés RSA de moins de 3 000 bits | https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf | 2026-10-22 |
| R1 F3.11 | `qcStatements`, `esi4-qtstStatement-1` | https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf ; https://www.rfc-editor.org/rfc/rfc3739.txt ; https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F3.16 | reconnaissance d'un jeton qualifié par une liste de confiance | https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf | 2026-10-22 |
| R1 F3.18 | vérification à long terme d'un jeton | https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf | 2026-10-22 |
| R1 F4.01 | liste des listes (LOTL) et listes nationales | https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf | 2026-10-22 |
| R1 F4.02 | type de service `TSA/QTST` | https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf | 2026-10-22 |
| R1 F4.03 | identité numérique de service (Sdi) comme ancre | https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf | 2026-10-22 |
| R1 F4.04 | statut `granted` et historique du service | https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf | 2026-10-22 |
| R1 F4.05 | TS 119 615 : emplacement et certificats de la LOTL | https://www.etsi.org/deliver/etsi_TS/119600_119699/119615/01.02.01_60/ts_119615v010201p.pdf | 2026-10-22 |
| R1 F4.06 | TS 119 615 §4.3.4 : correspondance entre service et certificat | https://www.etsi.org/deliver/etsi_TS/119600_119699/119615/01.02.01_60/ts_119615v010201p.pdf | 2026-10-22 |
| R1 F4.07 | TS 119 615 §4.6 : statut qualifié UE d'un jeton | https://www.etsi.org/deliver/etsi_TS/119600_119699/119615/01.02.01_60/ts_119615v010201p.pdf | 2026-10-22 |
| R1 F4.08 | LOTL observée : la Suisse n'y figure pas | https://ec.europa.eu/tools/lotl/eu-lotl.xml | 2026-10-22 |
| R1 F4.09 | liste de confiance suisse et organisme qui la tient | https://www.seco.admin.ch/en/csp-electronic-signature | 2026-10-22 |
| R1 F4.10 | règles du schéma suisse ; « recognised » | https://uri.tsl-switzerland.ch/TrstSvc/TrustedList/schemerules/CH/ | 2026-10-22 |
| R1 F4.11 | liste suisse observée ; certificat qui la signe | https://trustedlist.tsl-switzerland.ch/tsl-ch.xml ; https://trustedlist.tsl-switzerland.ch/tsl-signer-certificate/CH-TL-cert-DER.cer ; https://trustedlist.tsl-switzerland.ch/tsl-ch.sha2 | 2026-10-22 |
| R1 F5.01 | validité d'un certificat ; UTCTime et GeneralizedTime | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F5.02 | validation de chemin à un instant passé | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F5.03 | `basicConstraints` | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F5.04 | EKU et bits de `keyUsage` | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 F5.11 | OpenSSL : `TS_RESP_verify_signature` | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/crypto/ts/ts_rsp_verify.c ; `apps/ts.c` d'OpenSSL 3.0.13 : URL abrégée dans la note | 2026-10-22 |
| R1 F5.12 | OpenSSL : but « timestampsign » | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/crypto/x509/v3_purp.c | 2026-10-22 |
| R1 F5.13 | `openssl ts -verify` sans CRL du jeton ni OCSP | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/crypto/ts/ts_rsp_verify.c ; `apps/ts.c` d'OpenSSL 3.0.13 : URL abrégée dans la note | 2026-10-22 |
| R1 F5.14 | essais d'`openssl ts -verify` : dates et révocation | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R1 F6.01 | documentation d'`openssl ts` : `-digest`, `-cert` | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/doc/man1/openssl-ts.pod.in | 2026-10-22 |
| R1 F6.02 | `openssl ts -reply` ; `-token_out` | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/doc/man1/openssl-ts.pod.in | 2026-10-22 |
| R1 F6.08 | recette d'essai d'`openssl ts` | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R1 F6.09 | contenu du jeton d'essai d'OpenSSL | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R1 F7.01 | Sectigo : service d'horodatage qualifié | https://sectigo.com/resource-library/time-stamping-server | 2026-10-22 |
| R1 F7.02 | Sectigo : déclaration de la TSA eIDAS, CRL publiées | https://www.sectigo.com/uploads/legal/eIDAS/Sectigo-eIDAS-TSA-Disclosure-Statement-1.0.6.pdf | 2026-10-22 |
| R1 F7.03 | jeton qualifié réel de Sectigo | https://timestamp.sectigo.com/qualified ; jeton obtenu et analysé par la note, non publié | 2026-10-22 |
| R1 F7.04 | jeton de Sectigo hors DER strict | https://timestamp.sectigo.com/qualified ; analyse du jeton par la note, non publiée | 2026-10-22 |
| R1 F7.05 | liste espagnole : Sdi de Sectigo (AC R35) | https://tsl.digital.gob.es/TSL.xml | 2026-10-22 |
| R1 F7.06 | vérification hors ligne du jeton de Sectigo, `-partial_chain` | https://timestamp.sectigo.com/qualified ; https://tsl.digital.gob.es/TSL.xml ; essai de la note, non publié | 2026-10-22 |
| R1 F7.07 | Swisscom : horodatage par l'API AIS ; OCSP seul | https://trustservices.swisscom.com/hubfs/Website%20Files/Documents/Developer%20Documentation/Reference_Guide-All-in-Signing-Service-en.pdf | 2026-10-22 |
| R1 F7.09 | liste suisse : services d'horodatage de Swisscom | https://trustedlist.tsl-switzerland.ch/tsl-ch.xml | 2026-10-22 |
| R1 F7.10 | liste autrichienne : Swisscom TSS CA 4.1 | https://ec.europa.eu/tools/lotl/eu-lotl.xml ; liste autrichienne pointée par la LOTL ; son URL n'est pas écrite dans la note | 2026-10-22 |
| R1 (section 7.2) | RFC 5280 §3.3 : une entrée ne quitte pas une CRL avant d'avoir figuré sur une CRL régulière émise après la fin de validité du certificat révoqué ; texte lu dans la copie du digest | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 (section 9.4) | RFC 5280 §4.2.1 : identifiants des extensions de certificat | https://www.rfc-editor.org/rfc/rfc5280.txt | 2026-10-22 |
| R1 (section 12.5) | point non vérifié 7 (N-07) : signature XAdES de la LOTL et de la liste suisse non vérifiée ; conséquence 9 : identification de la liste lue (territoire, numéro de séquence, date d'émission) | https://ec.europa.eu/tools/lotl/eu-lotl.xml ; https://trustedlist.tsl-switzerland.ch/tsl-ch.xml ; point non vérifié de la note pour la signature | 2026-10-22 |
| R1 (section A.3) | résultats attendus d'`openssl ts -verify` établis par la note | https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/doc/man1/openssl-ts.pod.in (options de `openssl ts -verify`) ; https://raw.githubusercontent.com/openssl/openssl/openssl-3.0.13/crypto/x509/v3_purp.c (refus attendu pour T-8, selon le code lu) ; autres résultats attendus : essais de la note, non publiés ; fait non recoupable | 2026-10-22 |

### B.2 R2 — OpenTimestamps et Bitcoin

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R2-F01 | en-tête magique d'un fichier `.ots` (31 octets) | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/timestamp.py#L273 | 2026-10-22 |
| R2-F02 | ordre des champs après l'en-tête ; version majeure 1 | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/timestamp.py#L283-L341 | 2026-10-22 |
| R2-F03 | lecture : en-tête, version, opération, fin de fichier | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/timestamp.py#L327-L341 | 2026-10-22 |
| R2-F04 | encodage de la version : PyPI 0.4.5 et branche principale | https://github.com/opentimestamps/python-opentimestamps/blob/python-opentimestamps-v0.4.5/opentimestamps/core/timestamp.py#L319 ; https://github.com/opentimestamps/python-opentimestamps/commit/25fbaaff50ae2b35a6b5db4f19d4282f1a4be470 | 2026-10-22 |
| R2-F05 | version lue par les bibliothèques JavaScript, Java et Rust | https://github.com/opentimestamps/javascript-opentimestamps/blob/c07ba8be0dae4e8721a84f32820abf7b2547a6ce/src/detached-timestamp-file.js#L103-L107 ; https://github.com/opentimestamps/java-opentimestamps/blob/81863915ea218354e9c84cae0c522b85d1dc9f91/src/main/java/com/eternitywall/ots/DetachedTimestampFile.java#L101-L104 ; https://github.com/opentimestamps/rust-opentimestamps/blob/c87e3e18284fd1bb9456e50721aa4e2796aed057/src/ser.rs#L164-L171 | 2026-10-22 |
| R2-F06 | `varuint` en LEB128 | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/serialize.py#L143-L156 | 2026-10-22 |
| R2-F07 | `varuint` sans borne ni forme minimale | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/serialize.py#L192-L203 | 2026-10-22 |
| R2-F08 | `varbytes` et leurs bornes | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/serialize.py#L164-L166 | 2026-10-22 |
| R2-F10 | codes des opérations | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/op.py#L224-L349 | 2026-10-22 |
| R2-F12 | sémantique des opérations | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/op.py#L230-L231 ; https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/tests/core/test_op.py#L85-L108 | 2026-10-22 |
| R2-F13 | limites des opérations | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/op.py#L40 | 2026-10-22 |
| R2-F14 | `reverse` susceptible d'être retiré | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/op.py#L252-L253 | 2026-10-22 |
| R2-F15 | code d'opération inconnu : rejet du fichier | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/op.py#L164-L168 | 2026-10-22 |
| R2-F16 | arbre et branchements | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/timestamp.py#L101-L128 | 2026-10-22 |
| R2-F18 | profondeur maximale de l'arbre | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/timestamp.py#L131 ; https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/tests/core/test_timestamp.py#L117-L123 | 2026-10-22 |
| R2-F19 | encodage d'une attestation | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L22-L38 | 2026-10-22 |
| R2-F20 | `PendingAttestation` | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L163-L168 ; https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/tests/core/test_timestamp.py#L80 | 2026-10-22 |
| R2-F21 | `BitcoinBlockHeaderAttestation` | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L227-L230 | 2026-10-22 |
| R2-F22 | aucun identifiant de réseau dans l'attestation Bitcoin | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L254-L255 ; https://github.com/opentimestamps/opentimestamps-server/blob/0508e63fbd4d3a3fb716519f8fb1119fedde2c8a/README.md#L48-L50 | 2026-10-22 |
| R2-F23 | attestations Litecoin et Ethereum | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L309 ; https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/dubious/notary.py#L23-L29 | 2026-10-22 |
| R2-F24 | modules `opentimestamps.core` déclarés « consensus-critical » | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/README.md#L13-L18 | 2026-10-22 |
| R2-F25 | décomposition de `hello-world.txt.ots` | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/examples/hello-world.txt.ots | 2026-10-22 |
| R2-F26 | vérification : résultat des opérations contre `hashMerkleRoot` | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L279-L290 | 2026-10-22 |
| R2-F27 | ordre des octets de `hashMerkleRoot` | https://github.com/petertodd/python-bitcoinlib/blob/91e334d831fd16c60c932ad7df42c88fd6567c02/bitcoin/core/__init__.py#L514-L521 | 2026-10-22 |
| R2-F28 | hexadécimal affiché inversé dans Bitcoin Core | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/uint256.h#L72-L78 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/uint256.cpp#L11-L18 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/rpc/blockchain.cpp#L206 | 2026-10-22 |
| R2-F29 | inversion par la bibliothèque JavaScript | https://github.com/opentimestamps/javascript-opentimestamps/blob/c07ba8be0dae4e8721a84f32820abf7b2547a6ce/src/open-timestamps.js#L311 ; https://github.com/opentimestamps/javascript-opentimestamps/blob/c07ba8be0dae4e8721a84f32820abf7b2547a6ce/src/notary.js#L264-L270 | 2026-10-22 |
| R2-F30 | contrôle sur l'en-tête réel du bloc 358391 | https://blockstream.info/api/block-height/358391 ; explorateur tiers, source secondaire de contrôle croisé selon la note ; recalcul de la note, non publié | 2026-10-22 |
| R2-F31 | `ots verify` : déroulement et confiance au nœud | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/otsclient/cmds.py#L385-L491 | 2026-10-22 |
| R2-F33 | succès annoncé au jour près, en heure locale | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/otsclient/cmds.py#L431-L434 | 2026-10-22 |
| R2-F36 | modèle prévu : en-tête par hauteur ; réorganisation | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core/notary.py#L232-L252 | 2026-10-22 |
| R2-F37 | ce que prouve l'attestation ; précision estimée de `nTime` | https://petertodd.org/2016/opentimestamps-announcement | 2026-10-22 |
| R2-F38 | règle de consensus : médiane des 11 blocs précédents | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/validation.cpp#L4099-L4101 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/chain.h#L231-L245 | 2026-10-22 |
| R2-F39 | règle des 2 heures, relative à l'horloge du nœud | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/chain.h#L25-L29 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/validation.cpp#L4115-L4118 | 2026-10-22 |
| R2-F40 | heures de bloc non ordonnées ; BIP 113 | https://github.com/bitcoin/bips/blob/c0c5aea41e6a334d34db4ca87ae53bbfd7f268d1/bip-0113.mediawiki#L16-L37 | 2026-10-22 |
| R2-F43 | en-tête de 80 octets, ordre de sérialisation | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/primitives/block.h#L29-L42 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/serialize.h#L66-L70 | 2026-10-22 |
| R2-F44 | hachage du bloc : double SHA-256 | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/primitives/block.cpp#L14-L17 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/hash.h#L119-L128 | 2026-10-22 |
| R2-F45 | format compact de `nBits` | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/arith_uint256.h#L238-L256 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/arith_uint256.cpp#L176-L194 | 2026-10-22 |
| R2-F46 | preuve de travail sous la cible | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/pow.cpp#L146-L171 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/arith_uint256.cpp#L226-L232 | 2026-10-22 |
| R2-F47 | travail d'un bloc et travail cumulé | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/chain.cpp#L120-L133 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/validation.cpp#L4066-L4073 | 2026-10-22 |
| R2-F48 | chaînage et difficulté attendue | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/validation.cpp#L4094-L4097 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/headerssync.h#L21-L54 | 2026-10-22 |
| R2-F49 | réajustement de difficulté tous les 2016 blocs | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/pow.cpp#L14-L85 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/consensus/params.h#L130 ; https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/kernel/chainparams.cpp#L126-L131 | 2026-10-22 |
| R2-F51 | paramètres du réseau principal ; plus de points de contrôle | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/kernel/chainparams.cpp#L126 | 2026-10-22 |
| R2-F52 | travail minimal de chaîne : protection contre le déni de service | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/headerssync.h#L57-L84 | 2026-10-22 |
| R2-F53 | paramètres de regtest | https://github.com/bitcoin/bitcoin/blob/152a55397e451fed9c10041bddf01aa6839847d5/src/kernel/chainparams.cpp#L603-L633 | 2026-10-22 |
| R2-F57 | livre blanc §11 : probabilité de rattrapage | https://bitcoin.org/bitcoin.pdf | 2026-10-22 |
| R2-F58 | livre blanc §3 : serveur d'horodatage | https://bitcoin.org/bitcoin.pdf | 2026-10-22 |
| R2-F59 | paquet PyPI `opentimestamps` 0.4.5 et sa licence | https://pypi.org/pypi/opentimestamps/json ; https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/setup.py#L35 | 2026-10-22 |
| R2-F67 | cas limites observés avec la bibliothèque Python 0.4.5 | essai de la note, non publié ; fichiers essayés : https://github.com/opentimestamps/opentimestamps-client/tree/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/examples ; bibliothèque : https://pypi.org/pypi/opentimestamps/json ; résultats non recoupables publiquement | 2026-10-22 |
| R2-F69 | protocole REST des calendriers | https://github.com/opentimestamps/python-opentimestamps/blob/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/calendar.py#L55-L105 ; https://github.com/opentimestamps/opentimestamps-server/blob/0508e63fbd4d3a3fb716519f8fb1119fedde2c8a/otsserver/rpc.py#L43-L44 | 2026-10-22 |
| R2-F73 | délais par défaut du serveur de calendrier | https://github.com/opentimestamps/opentimestamps-server/blob/0508e63fbd4d3a3fb716519f8fb1119fedde2c8a/otsd#L78-L88 ; https://github.com/opentimestamps/opentimestamps-server/blob/0508e63fbd4d3a3fb716519f8fb1119fedde2c8a/otsserver/stamper.py#L384-L387 | 2026-10-22 |
| R2-F74 | délai annoncé à l'utilisateur | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/README.md#L49-L50 ; https://petertodd.org/2016/opentimestamps-announcement | 2026-10-22 |
| R2-F75 | mise à niveau d'une preuve par le client | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/otsclient/cmds.py#L244-L318 | 2026-10-22 |
| R2-F76 | réponse réelle du calendrier Alice | https://alice.btc.calendar.opentimestamps.org/timestamp/57cfa5c46716df9bd9e83595bce439c58108d8fcc1678f30d4c6731c3f1fa6c79ed712c66fb1ac8d4e4eb0e7 | 2026-10-22 |
| R2-F77 | confidentialité : nonce et arbre de Merkle avant soumission | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/otsclient/cmds.py#L171-L182 | 2026-10-22 |
| R2 (section 10.4) | code de Bitcoin Core lu par la note (`src/arith_uint256.cpp`, `src/pow.cpp`) | https://github.com/bitcoin/bitcoin | 2026-10-22 |
| R2 (section 10.6) | point non vérifié 5 : aucune borne de précision de `nTime` dans le code lu | https://petertodd.org/2016/opentimestamps-announcement ; point non vérifié de la note | 2026-10-22 |
| R2 (section 12.5) | point non vérifié 6 : version publiée de Bitcoin Core sans points de contrôle | https://github.com/bitcoin/bitcoin ; point non vérifié de la note | 2026-10-22 |
| R2 (section 13.2) | conséquence 10 : nombre de calendriers exigé par défaut par le client | https://github.com/opentimestamps/opentimestamps-client | 2026-10-22 |

### B.3 R3 — Registre et contrôle 8

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R3 F1 | `BFTBlockHash` : préimage de 212 octets | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F2 | mode BFT : seule fonction de hachage du bloc | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F4 | expérience 1 : RLP de l'en-tête contre `BFTBlockHash` (bloc 8316) | expérience de la note sur le réseau de développement, non publiée ; `test/fixtures/certificat-commit/bloc-8316.json` (présent dépôt) ; go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F5 | champs servis hors préimage, constants et non engagés | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F7 | champs comparés par le validateur qui reçoit une proposition | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F8 | horodatage du bloc : horloge du proposant, bornée | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F11 | condensé signé par chaque validateur | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F12 | signature secp256k1 `R‖S‖V`, S bas | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F13 | contrôles de `VerifyEnvelope` | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F14 | hachage du jeu de validateurs (`valsetHash`) | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F15 | quorum `Quorum2f1` | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F16 | condition de décision du moteur de consensus | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F18 | corps signé de la proposition : engagements et transactions brutes | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement ; expérience de la note sur le réseau de développement, non publiée | 2026-10-22 |
| R3 F20 | `canonical.matchesCertificate`, égalité faite par le nœud | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F21 | procédure hors ligne du correctif RPC : égalité de chaînes | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F22 | vérificateur JavaScript de certificat : ce qu'il vérifie et ignore | `scripts/lib/certificat-commit.mjs` (présent dépôt) ; `scripts/verify/certificat-commit.mjs` (présent dépôt) ; exécution de la note sur un certificat capturé, non publiée | 2026-10-22 |
| R3 F23 | calcul de `receiptsRoot` par le nœud | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F24 | encodage de consensus d'un reçu ; clés du trie | go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 F25 | EIP-2718 : reçu typé ou legacy | https://eips.ethereum.org/EIPS/eip-2718 | 2026-10-22 |
| R3 F26 | expérience 3 : `receiptsRoot` recalculé sur quatre blocs | expérience de la note sur le réseau de développement, non publiée ; go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 F27 | expérience 3 : preuve Merkle-Patricia d'un reçu | expérience de la note sur le réseau de développement, non publiée ; go-ethereum v1.17.0, paquet `trie` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 F28 | reçu servi sans `logsBloom` | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F29 | `eth_getBlockReceipts` rend un tableau vide | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F30 | `debug_getRawReceipts` et `eth_getProof` non servis | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement ; observation de la note sur le réseau de développement, non publiée | 2026-10-22 |
| R3 F32 | contre-épreuve : reçu falsifié | expérience de la note sur le réseau de développement, non publiée ; go-ethereum v1.17.0, paquets `types` et `trie` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 F33 | événement `PeriodSubmitted` et son topic0 | `contracts/PeriodRegistry.sol` (présent dépôt) | 2026-10-22 |
| R3 F34 | événement `Anchored` et son topic0 | `contracts/AttestationRegistry.sol` (présent dépôt) | 2026-10-22 |
| R3 F35 | événement `RecorderRegistered` et son topic0 | `contracts/RecorderRegistry.sol` (présent dépôt) | 2026-10-22 |
| R3 F36 | conditions d'émission de `PeriodSubmitted` | `contracts/PeriodRegistry.sol` (présent dépôt) | 2026-10-22 |
| R3 F38 | expérience 3 : journaux décodés d'un parcours complet | expérience de la note sur le réseau de développement, non publiée ; `scripts/lib/noortrace.mjs` (présent dépôt) ; `contracts/` (présent dépôt) | 2026-10-22 |
| R3 F39 | inscription, ancre et clôture dans trois blocs certifiés | expérience de la note sur le réseau de développement, non publiée ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 F41 | état passé servi sans preuve | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F43 | rétention des certificats : 300 000 hauteurs | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F44 | fenêtre de tête avant l'écriture du certificat | `chain/README.md` (présent dépôt) ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F45 | suiveur : relais sans certificat | `chain/docker/README.md` (présent dépôt) ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 F46 | cadence mesurée du réseau de développement | mesure de la note sur le réseau de développement, non publiée ; aucune source primaire publique dans la note ; fait non recoupable ; `chain/README.md` (présent dépôt) pour la valeur annoncée | 2026-10-22 |
| R3 F47 | taille d'un certificat ; transactions brutes embarquées | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement ; mesure de la note, non publiée | 2026-10-22 |
| R3 NV1 | sûreté d'un certificat réduit aux precommits | point non vérifié de la note ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 NV2 | hypothèse de sûreté BFT (au plus f validateurs fautifs) | point non vérifié de la note ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 NV5 | provenance du jeu de validateurs | point non vérifié de la note ; code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 NV7 | reproductibilité du code des contrats déployés | point non vérifié de la note ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 (section 11.2.1) | capture du 2026-10-22 (blocs 15936 et 15940) | expérience de la note sur le réseau de développement, non publiée ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 (section 11.3.1) | conséquence 2 : champs du hachage pris dans l'en-tête servi, non dans le corps de la proposition, dont le validateur ne compare ni `gasLimit`, ni `baseFeeHex`, ni un `parentHash` nul | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 (section 11.3.2) | capture de la note (blocs 15932, 15936, 15940 et 16324) | expérience de la note sur le réseau de développement, non publiée ; go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 (section 11.4) | conséquence 6 : adresse émettrice d'un journal, engagée par l'encodage du reçu | go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R3 (section 11.8) | conséquence 6 : index de transaction engagé par la clé du trie, non le hachage de transaction ; conséquence 8 : absence d'un événement non prouvable, le `logsBloom` du bloc n'étant pas engagé | conséquence 6 : go-ethereum v1.17.0, paquet `types` (code public ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable ; conséquence 8 : code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 (section 12.5) | conséquence 9 : élagage des certificats des blocs de déploiement | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |
| R3 (section 13.3) | conséquence 9 : élagage des certificats des blocs de déploiement | code de noorcore (dépôt privé), non publiable ; fait non recoupable publiquement | 2026-10-22 |

### B.4 R4 — Construction et sûreté

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R4 F1.04 | construction reproductible sans cgo, avec `-trimpath` | https://go.dev/blog/rebuild | 2026-10-22 |
| R4 F1.05 | `-trimpath` retire les chemins de fichiers | https://pkg.go.dev/cmd/go | 2026-10-22 |
| R4 F1.07 | archives : heure fixée, identifiants effacés | https://go.dev/blog/rebuild | 2026-10-22 |
| R4 F1.08 | reproductibilité, complément de SLSA | https://go.dev/blog/rebuild | 2026-10-22 |
| R4 F1.09 | `-buildvcs` et estampille VCS | https://pkg.go.dev/cmd/go | 2026-10-22 |
| R4 F1.11 | `go version -m` | https://pkg.go.dev/cmd/go | 2026-10-22 |
| R4 F1.12 | `-ldflags` ; `-buildid` | https://pkg.go.dev/cmd/go ; https://pkg.go.dev/cmd/link | 2026-10-22 |
| R4 F1.13 | `GOFLAGS` et `GOENV=off` | https://pkg.go.dev/cmd/go | 2026-10-22 |
| R4 F1.16 | essai : reproductibilité observée ; chemins absolus sans `-trimpath` | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable ; programme essayé : vérificateur indépendant de CT-1, `spec/vecteurs/ct-1/verificateur-independant/` (présent dépôt) | 2026-10-22 |
| R4 F1.17 | essai : estampille VCS et modification non commitée | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F1.18 | `GOTOOLCHAIN` | https://go.dev/doc/toolchain | 2026-10-22 |
| R4 F1.22 | essai : vendoring et construction sans réseau | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip ; module de l'essai ; essai de la note, non publié | 2026-10-22 |
| R4 F1.24 | spécification `SOURCE_DATE_EPOCH` | https://reproducible-builds.org/specs/source-date-epoch/ | 2026-10-22 |
| R4 F1.25 | essai : Go 1.24.7 ne lit pas `SOURCE_DATE_EPOCH` | essai de la note, non publié, sur le code source de Go 1.24.7 ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F1.26 | image de conteneur épinglée par empreinte | https://docs.docker.com/build/building/best-practices/ ; https://docs.docker.com/reference/cli/docker/image/pull/ | 2026-10-22 |
| R4 F1.27 | actions de CI épinglées par SHA de commit | https://docs.github.com/en/actions/reference/security/secure-use | 2026-10-22 |
| R4 F1.28 | versions de Go publiées et maintenues | https://go.dev/dl/?mode=json ; https://go.dev/doc/devel/release | 2026-10-22 |
| R4 F2.02 | `Certificate.Verify` avec `Roots` nul | https://pkg.go.dev/crypto/x509 | 2026-10-22 |
| R4 F2.03 | appel du vérificateur de la plate-forme | code source de Go 1.24.7, paquet `crypto/x509` (distribution officielle ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F2.04 | Windows : drapeaux passés à `CertGetCertificateChain` | code source de Go 1.24.7, paquet `crypto/x509` (distribution officielle ; aucune URL dans la note) ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F2.05 | Windows : récupération réseau des émetteurs (AIA) | https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain | 2026-10-22 |
| R4 F2.06 | macOS : récupération réseau des certificats manquants | <https://developer.apple.com/documentation/security/sectrustsetnetworkfetchallowed(_:_:)> ; code source de Go 1.24.7, paquet `crypto/x509` (distribution officielle ; aucune URL dans la note) | 2026-10-22 |
| R4 F2.09 | essai : sonde x509 sans appel réseau ; racines système lues sous Linux | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F2.11 | essai : absence de symboles de résolution réseau dans le binaire | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R4 F2.12 | essai : vérificateur de CT-1 sans appel réseau | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable ; programme essayé : vérificateur indépendant de CT-1, `spec/vecteurs/ct-1/verificateur-independant/` (présent dépôt) | 2026-10-22 |
| R4 F2.13 | `unshare -n` et `-r` | https://man7.org/linux/man-pages/man1/unshare.1.html | 2026-10-22 |
| R4 F2.14 | espace de noms réseau | https://man7.org/linux/man-pages/man7/network_namespaces.7.html | 2026-10-22 |
| R4 F2.15 | `strace -f` et classe `%network` | https://man7.org/linux/man-pages/man1/strace.1.html | 2026-10-22 |
| R4 F3.02 | licence BSD à trois clauses de golang.org/x/crypto | https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.zip | 2026-10-22 |
| R4 F3.03 | `x/crypto/sha3` et Keccak hérité | https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.zip | 2026-10-22 |
| R4 F3.04 | module secp256k1/v4 v4.4.1 : version, licence ISC | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@latest ; https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip | 2026-10-22 |
| R4 F3.05 | format compact de signature de decred | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip | 2026-10-22 |
| R4 F3.06 | contrôles de `RecoverCompact` | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip | 2026-10-22 |
| R4 F3.07 | empreinte tronquée par `SetByteSlice` | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip | 2026-10-22 |
| R4 F3.08 | essai : signature compacte, S haut accepté | https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.4.1.zip ; module de l'essai ; essai de la note, non publié | 2026-10-22 |
| R4 F3.10 | lignes `go.sum` attestées par la base de sommes | https://sum.golang.org/lookup/golang.org/x/crypto@v0.58.0 ; entrée de secp256k1/v4 : URL abrégée dans la note | 2026-10-22 |
| R4 F3.11 | politique de licences tierces de l'ASF : catégorie A | https://www.apache.org/legal/resolved.html | 2026-10-22 |
| R4 F3.12 | licence Apache 2.0 §4(d) : fichier NOTICE | https://www.apache.org/licenses/LICENSE-2.0.txt | 2026-10-22 |
| R4 F3.13 | avis de la base vulndb pour golang.org/x/crypto | https://vuln.go.dev/index/db.json ; https://vuln.go.dev/index/modules.json ; avis individuels GO-… : URL abrégée dans la note | 2026-10-22 |
| R4 F3.14 | avis de la bibliothèque standard (GO-2025-4011, GO-2026-5972, GO-2026-4947, GO-2026-6809, GO-2025-4009, GO-2022-0433) | https://vuln.go.dev/ | 2026-10-22 |
| R4 F3.15 | codes de sortie de govulncheck | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | 2026-10-22 |
| R4 F4.01 | `sha256sum -c` et `--strict` | https://www.gnu.org/software/coreutils/manual/html_node/md5sum-invocation.html ; aide de `sha256sum` (GNU coreutils 9.4) et essai de la note | 2026-10-22 |
| R4 F4.02 | minisign | https://jedisct1.github.io/minisign/ | 2026-10-22 |
| R4 F4.06 | attestations d'artefacts GitHub | https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations ; https://github.com/actions/attest-build-provenance ; https://github.com/actions/attest | 2026-10-22 |
| R4 F4.07 | `gh attestation verify` | https://cli.github.com/manual/gh_attestation_verify | 2026-10-22 |
| R4 F4.08 | vérification hors ligne d'une attestation GitHub | https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline | 2026-10-22 |
| R4 F4.09 | publications immuables GitHub | https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases ; https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/verifying-the-integrity-of-a-release | 2026-10-22 |
| R4 F5.01 | fuzzing natif de Go | https://go.dev/doc/security/fuzz/ | 2026-10-22 |
| R4 F5.02 | échecs de fuzzing et corpus rejoué | https://go.dev/doc/security/fuzz/ | 2026-10-22 |
| R4 F5.03 | essai : fuzzing d'un lecteur DER borné | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable ; graine : jeton de Sectigo (R1 F7.03) | 2026-10-22 |
| R4 F5.04 | `encoding/asn1` : ce qu'il refuse et ce qu'il ignore | https://pkg.go.dev/encoding/asn1 ; code source de Go 1.24.7, paquet `encoding/asn1` (aucune URL dans la note) | 2026-10-22 |
| R4 F5.05 | cryptobyte : lecture DER stricte | https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.zip | 2026-10-22 |
| R4 F5.06 | essai : cryptobyte et `encoding/asn1` sur le jeton de Sectigo | essai de la note, non publié ; aucune source primaire publique dans la note ; fait non recoupable ; jeton essayé : R1 F7.03 | 2026-10-22 |
| R4 F5.10 | débordement de pile non récupérable | https://pkg.go.dev/runtime/debug ; https://go.dev/ref/spec | 2026-10-22 |
| R4 F5.11 | cibles de fuzzing de sigstore-go | https://github.com/sigstore/sigstore-go | 2026-10-22 |
| R4 F6.05 | `ots verify` : messages et code de retour | https://github.com/opentimestamps/opentimestamps-client/blob/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/otsclient/cmds.py ; https://docs.python.org/3/library/argparse.html | 2026-10-22 |
| R4 (section 14.1) | point non vérifié 1 : récupération AIA sous Windows et macOS, non observée | https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain ; <https://developer.apple.com/documentation/security/sectrustsetnetworkfetchallowed(_:_:)> ; https://pkg.go.dev/crypto/x509 ; point non vérifié de la note | 2026-10-22 |
| R4 (section 14.2) | point non vérifié 4 : `unshare -rn` sans privilège, non essayé | https://man7.org/linux/man-pages/man1/unshare.1.html ; point non vérifié de la note | 2026-10-22 |
| R4 (section 14.3) | essais de reproductibilité de la note | essais de la note, non publiés ; aucune source primaire publique dans la note ; fait non recoupable ; programme essayé : vérificateur indépendant de CT-1, `spec/vecteurs/ct-1/verificateur-independant/` (présent dépôt) | 2026-10-22 |
