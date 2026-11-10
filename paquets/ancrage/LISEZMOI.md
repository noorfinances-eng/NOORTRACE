# @noortrace/ancrage

Composant d'ancrage de NOORTRACE, étape 5 de la phase 2 : client RFC 3161 et
vérification des jetons à l'acquisition, client OpenTimestamps, ancre des
points et des périodes au registre de CT-4, planificateur à file durable,
serveur RFC 3161 interne non qualifié, composant temps réel qui les assemble
pour l'enregistreur de CT-2, tels que les fixe la spécification normative
[CT-5](../../spec/CT-5-ancrage.md) (avec les sections de CT-4, CT-6 et CT-1
qu'elle réutilise).

Le paquet est écrit à neuf depuis le seul texte des spécifications ; il ne
reprend rien de l'implémentation de référence qui a produit les vecteurs
(`scripts/lib/**`). Les vecteurs de `spec/vecteurs/ct-5` (et ceux de CT-1,
CT-4 et CT-6 que CT-5 réutilise) sont les juges : le paquet les rejoue tous.
Cinq développeurs ont écrit les cinq sous-modules en parallèle, sans se
lire ; ils ont ensuite été assemblés dans le composant temps réel, complétés
de l'exportateur (§10) et branchés dans le démon de l'enregistreur
(`@noortrace/enregistreur`, `anchoring.ancrage`), éprouvés par les épreuves
CT-9 de l'étape 5, corrigés après la relecture adversariale, puis alignés sur
les révisions CT-5 0.4 (règles) et 0.5 (textuelle), et CT-6 0.5. Le contrat du paquet, aligné sur le code
livré, est [`INTERFACES.md`](INTERFACES.md) ; les sections « Lectures » et
« Restes » de ce document disent ce qui a été tranché et ce qui ne l'est pas.

## Ce que fait le paquet

| Sous-module | Rôle | Règles |
|---|---|---|
| `src/rfc3161/` | requête `TimeStampReq` octet pour octet, transport TLS, lecture bornée de la réponse, T-1 à T-9 à l'acquisition, T-10 différée sur les CRL capturées, classement des erreurs, dépôt des pièces et `acquisitions.ndjson`, fiche de prestataire et épreuve d'acceptation | CT-5 §5, §10.2, §11 ; CT-6 §9, §12, §13, §15 |
| `src/ots/` | format `.ots` (lecture stricte, écriture dans l'ordre de la bibliothèque de référence, fusion), O-1 à O-5 et O-7, soumission aux calendriers, mise à niveau, fichier d'en-têtes Bitcoin, dépôt des preuves | CT-5 §6 ; CT-6 §10, §13 |
| `src/planificateur/` | configuration `ancrage-v0` (AN-1) et projection, automate déterministe d'EX-8.16 (six sortes de demandes, dix états, treize actions, dix entrées, trois méthodes hors schéma), file durable, échéances, cadence et alertes de 8.9 (AN-2), admission par le noyau (AN-3), comptages, coût, complétude au registre, supervision | CT-5 §4, §5.3, §6.1, §8, §9.2, §10.2, §12 |
| `src/registre/` | clé de chaîne, encodages de CT-4 §6, transactions de type 2, client JSON-RPC, `Envoyeur` (`anchor`, `submitPeriod`, renvoi, remplacement), capture CP-1 à CP-6, export des parties du registre | CT-5 §9 ; CT-4 §6 à §9 ; CT-6 §11 |
| `src/serveur-interne/` | autorité RFC 3161 de développement (AC, unité, CRL), réponse `granted` ou refus, frontal HTTP local ou TLS mutuel, compteur de série durable, binaire `noortrace-tsa-interne` | CT-5 §7 ; RFC 3161, RFC 5816 |
| `src/composant.mjs` | le composant temps réel : interface `ComposantAncrage` de l'enregistreur, planificateur et file sous `queue.path`, exécution des actions avec les clients A, B, D, réinjection des résultats, tics et reprises sur l'horloge injectée, relecture du stockage au démarrage, T-10 différée, nonce OpenTimestamps durable, supervision | CT-5 §4.7, §5.4, §8 ; CT-2 §14.2, §15.2, §17 |
| `src/cli.mjs`, `bin/noortrace-ancrage` | `configuration`, `serie`, `cout`, `trace`, `fiche`, `acquisitions`, `completude` | CT-5 EX-8.13, EX-10.6, EX-10.7, EX-12 |

Aucun module de `src/` ne lit l'horloge ni l'aléa du système ni un secret :
tout est injecté (règle 2 d'`INTERFACES.md`) ; les binaires `bin/` branchent
`Date.now`, `performance.now`, `setTimeout` et `crypto.randomBytes`.

## Utilisation

```js
import { creerComposantAncrage } from "@noortrace/ancrage";

const composant = creerComposantAncrage({
  configuration,        // document ancrage-v0 (CT-5 EX-4.8), secrets par emplacement
  profil: "production", // profil de CT-2 §15
  checkpointIntervalEnregistreur: 60,
  contexte: { org_id, journal_id, epoque, racineStockage, secrets, clePublique, lireSerie, lireHashesPeriode, listerPeriodes, listerPoints, cleChaine, signaturesCloture },
  horloge: { murale, monotone, programmer },
  aleatoire: (n) => new Uint8Array(crypto.randomBytes(n)),
  journal,              // JournalExploitation de l'enregistreur
  clients: { registre: { points, identifiants, instance, repertoireEnvois } },
});
await composant.demarrer();                 // refuse une configuration invalide (AN-1) : l'enregistreur continue
composant.remettrePoint(remise);            // à chaque point écrit et synchronisé (CT-2 EX-12.27) ; rend la main sans attendre le réseau
composant.remettreCloture(remise);          // à chaque clôture
```

La rubrique F d'`INTERFACES.md` décrit chaque membre de `contexte`, de
`clients` et de l'horloge, et ce que le composant fait de chaque action du
planificateur.

```sh
noortrace-ancrage configuration ancrage.json --profil production --checkpoint-interval 60
noortrace-ancrage serie --configuration ancrage.json --periode 1793869200 --points points/periode-1793869200.ndjson --cles cles.json --acquisitions ancres/periode-1793869200/acquisitions.ndjson
noortrace-ancrage cout --role second_rang --activite 0.25            # unités symboliques, jamais un prix
noortrace-ancrage trace spec/vecteurs/ct-5/planification/heure-nominale-reference.json
noortrace-ancrage fiche --configuration ancrage.json --id qtsa-principal --epreuve --sortie prestataire-qtsa-principal.json
noortrace-ancrage acquisitions ancres/periode-1793869200/acquisitions.ndjson
noortrace-ancrage completude entrees.json
noortrace-tsa-interne init --repertoire /var/lib/noortrace/tsa --politique 1.3.6.1.4.1.99999.1.1 --crl-url https://crl.exploitant.example/tsa.crl
```

L'exportateur (section « Exportateur ») s'appelle depuis
l'enregistreur, qui détient les sept parties de CT-1 du dossier :

```js
import { exporterDossier, etatAncresPeriode, reexportsDus } from "@noortrace/ancrage/exportateur";

const r = exporterDossier({
  event: { seq, hash }, org_id, journal_id,
  partiesBase, raisonsBase,             // evenement.json, voisins.json, chemin.json, manifeste.json, manifeste.sig, cles.json, approbations.json
  hashes, leafIndex, manifeste, periodHash, serie,
  racineStockage,                        // dépôts d'EX-5.14 : <racine>/<org>/<journal>/ancres/periode-<P>/
  registre: { repertoireCaptures, jeux, source, inscriptions },   // null sans registre
  destination, generated_at,
});
// r.dossier (dossier.json), r.point (point couvrant, rang), r.pieces, r.raisons, r.resume (entrée de reexportsDus)
const dus = reexportsDus({ dossiersProduits: [r.resume], etatAncres: (P) => etatAncresPeriode({ racineStockage, orgId, journalId, periodStart: P, serie, repertoireCaptures, periodHash }) });
```

Dans le démon, `noortrace` passe par lui dès qu'`anchoring.ancrage` est
configuré (`Coeur.exporterDossier`, `Coeur.reexportsDus`) ; `noortrace-ctl
ancrage etat|metriques|retirer-qualification <id>` interroge le composant
branché (LISEZMOI de l'enregistreur, section « Ancrage »).

## Configuration

Le document `ancrage-v0` (CT-5 §4.4, schéma `spec/schemas/ancrage-v0.schema.json`,
copie embarquée dans `src/planificateur/schemas-ancrage.mjs`) est validé au
démarrage et à chaque rechargement : schéma, puis les huit règles d'EX-4.9
(cadence égale à celle de l'enregistreur et diviseur de 3600 ; un principal,
au plus un secours, identifiants distincts ; `c_T` multiple de `c_K` et
diviseur de 3600 ; `https://` partout sauf `http://` du seul rôle `interne`
vers une adresse locale, dans tout profil, et `auth` `aucune` de même ; en
production `provider_role ≠ aucun`, `registry.checkpoints ≠ aucun`,
OpenTimestamps activé, principal et secours qualifiés ; deux
calendriers et une liste blanche ; rétention ≥ 10 ans, `initial_ms ≤ max_ms`,
`interval_s ≥ 60` ; le rôle désigné pour les points existe ; chaque PEM se
lit), puis la présence des secrets résolus que les prestataires et la source
d'en-têtes désignent (règle `secrets`). Les secrets (`auth.secret`,
`headers_source.auth`) sont des références d'emplacement de CT-2 §15.2 ; le
composant les reçoit en octets dans `contexte.secrets` et ne lit rien
lui-même.

## Fichiers sur disque

```text
<queue.path>/file-<epoque>.ndjson                       file durable (une ligne JCS intégral par état d'une demande, 32 tentatives au plus et attempts_total, compactée à la clôture et au-delà de queue.compact_bytes, EX-8.5 règles 5 et 7)
<queue.path>/file-<epoque>.ndjson.compactage            fichier neuf d'un compactage, renommé sur le fichier courant ; resté d'un arrêt, supprimé au démarrage (EX-8.12)
<racine>/<org_id>/<journal_id>/ancres/periode-<period_start>/
  rfc3161/<objet>-<provider_id>-<attempt_id>.tsq        requête telle qu'envoyée
  rfc3161/<objet>-<provider_id>-<attempt_id>.tsr        réponse telle que reçue (réponse d'erreur comprise)
  rfc3161/<objet>-<provider_id>-<attempt_id>.der        jeton extrait, tel quel
  rfc3161/<objet>-<provider_id>-<attempt_id>.crl.pem    CRL capturées après genTime (T-10 différée), un bloc PEM par certificat du chemin
  ots/<objet>-<n>.ots                                   preuve OpenTimestamps, version n
  ots/<objet>.nonce                                     nonce OpenTimestamps durable (EX-6.2 : même engagement au rejeu)
  entetes-bitcoin.json                                  fichier d'en-têtes de la période (EX-6.8)
  acquisitions.ndjson                                   enregistrements d'acquisition (EX-5.13), ajout seul ; la T-10 différée ajoute une ligne par tentative promue
<repertoireEnvois>/envoi-<hash>.json, issue-<hash>.json, bloc-<h>.json, recu-<hash>.json, certificat-<h>.json, capture-<h>-<index>-<rôle>.json   (CT-4 §8.6, §9.4)
```

`<objet>` vaut `manifeste` ou `point-<checkpointHash sans 0x>` ;
`<attempt_id>` est `<kind>:<16 premiers hex de l'empreinte>:<n>` ; rien n'est
jamais réécrit ni supprimé, hors le fichier courant de la file, remplacé par
sa forme compactée (renommage atomique), et le `.compactage` resté d'un arrêt
(CT-5 révision 0.6, EX-8.5 règle 5, EX-8.14) ; le jeton remis au dossier est le `.der` de la
tentative que la dernière ligne d'`acquisitions.ndjson` marque `promoted`
sans `revoked` (EX-5.8, `DepotAncres.promu`).

## Vecteurs rejoués

| Famille | Cas | Par | Résultat |
|---|---|---|---|
| `ct-5/requetes/requetes.json`, `refusees.json` | 6 requêtes, 5 refus | `rfc3161`, `planificateur` | octets, SHA-256, nonce, messages identiques |
| `ct-5/reponses/reponses.json` | 28 cas | `rfc3161` | issue, code, classe, avertissements, jeton extrait, attente de reprise identiques |
| `ct-6/rfc3161/attendu.json` (CT-6 révision 0.5) | 28 jetons, 41 cas (T-1 à T-10, faits), dont `t1-cle-longueur-non-minimale` et `t1-extension-mal-formee` (T-1 `echoue`) | `rfc3161` | identiques |
| `ct-6/dossiers/*` | 91 jetons de période, 17 jetons de points | `rfc3161` | conformes |
| `ct-5/ots/*` | 3 preuves, paire de mise à niveau | `ots` | octets identiques ; resérialisés à l'identique par `python-opentimestamps` |
| `ct-6/ots/attendu.json` (CT-6 révision 0.5), dossiers | 13 preuves, 21 cas O-1 à O-5, O-7, dont `o1-attestation-en-double` (O-1 `echoue`, `doublon`) ; preuves des dossiers | `ots` | identiques |
| `ct-5/planification/*.json` (CT-5 révision 0.6) | 24 traces, dont `file-fenetre-32` et `file-fenetre-32-redemarrage` | `planificateur`, binaire (`trace`) | `expected` et `queue_after` identiques (JCS) |
| `ct-5/reprise/*.ndjson` | 7 scénarios, dont `file-fenetre-32-redemarrage` | `planificateur` | relecture et fusion des époques octet pour octet |
| `ct-5/cout/cout.json`, `ct-5/completude/completude.json`, `ct-5/constantes.json` | 11, 6 cas ; constantes | `planificateur`, binaire | égaux |
| `ct-1/points-de-controle/*`, `manifestes/`, `cles/` | 3 séries valides, 10 invalides | `planificateur`, binaire | admises ; refusées sur la règle attendue |
| `ct-4/*` (sauf `inscription`), `ct-6/registre/*` | identifiants, doctypes, empreintes, condensés, appels, transactions, demandes, capture (17), manifestes (24), trie, attendu | `registre` | octet pour octet |
| `ct-6/dossiers/*/points-de-controle.json`, `ct-1/dossier/*` | chaque dossier qui porte la partie : point couvrant retrouvé depuis la série et les ancres fournies (EX-10.2), partie reconstruite | exportateur | octet pour octet (`checkpoint_hash`, rang, ancres base64, `registry`) |
| `ct-6/dossiers/valide-point-de-controle-complet` | dossier entier réexporté depuis les pièces du vecteur (treize parties, `dossier.json`, `registre.json` avec `ancre_point_de_controle`) | exportateur | identique ; accepté par le vérificateur JavaScript et par le binaire Go, même énoncé |

## Essais

```sh
npx hardhat --config hardhat.config.mjs test test/ancrage-*.test.js
```

Conditions des essais en attente (nommées dans le titre de l'essai) :
`NOORTRACE_TSA_PUBLIQUE=1` (autorités publiques : client RFC 3161, composant,
épreuves des prestataires réels) ; `NOORTRACE_RESEAU_PUBLIC=1` (agrégateurs
OpenTimestamps) ; `NOORTRACE_OTS_PYTHON` ou `python3` avec `opentimestamps`
0.4.5 (confrontation des `.ots`) ; `NOORTRACE_GO_BIN` ou
`NOORTRACE_VERIFIER_BIN` (vérificateur Go de CT-6) ; réseau de développement
debout (`bash chain/scripts/dev-net.sh start`) et
`NOORTRACE_PARCOURS_REGISTRE` (sortie d'un `npm run e2e:registre -- --garder-reseau --sortie <répertoire> --verificateur-go <binaire>`)
pour les essais du registre réel (registre, composant, parcours de
l'enregistreur) ; IPv6 (serveur interne) ; `openssl` (TLS d'essai,
confrontations) ; Docker avec l'image LocalStack épinglée (TE-14 sur le
support WORM réel, complément TM-16).

Épreuves CT-9 de l'étape 5 : `test/ancrage-prestataires-reels.test.js`
(TI-16 : SwissSign et DFN par le transport de production, T-1 à T-10, fiche,
`min_interval_ms` par un relais local, preuve `.ots` auprès des agrégateurs
publics ; en attente hors `NOORTRACE_TSA_PUBLIQUE=1` et
`NOORTRACE_RESEAU_PUBLIC=1`), `test/enregistreur-journal-soi.test.js` (TE-14 :
JS-1 à JS-12 sur le démon réel, rotation et disque plein du journal
d'exploitation, JS-9 et JS-10 et complément TM-16 sur LocalStack), les
compléments TI-17, TA-41 et TA-62 de `test/enregistreur-ancrage-exigences.test.js`,
et la campagne de mesures `scripts/e2e/mesure-ancrage.mjs` (`collecter`,
`complements`, `rapport` ; rapport de la campagne
`spec/vecteurs/ct-9/mesures/rapport-2026-11-09-ancrage.json`, validé par
`node scripts/tests/mesures.mjs`). Le pilote du démon enfant
(`test/fixtures/enregistreur-ancrage/demon.mjs`) reçoit en plus les commandes
`decaler-murale`, `rotation`, `controles`, `worm`, `metriques` ; les
fixtures offrent `lireParcours`, `inscrireJournal`, `monterDemonReseauReel`,
`demandeClotureParcours` et `sansReseau`.

L'exportateur est éprouvé par `test/ancrage-exportateur.test.js` ; le
branchement dans l'enregistreur par `test/enregistreur-ancrage-parcours.test.js`
(TE-12 de CT-9 hors réseau public : démon `noortrace` réel, enfant du test,
horloge réglable partagée ; puis la variante complète sur le réseau de
développement réel : journal neuf inscrit par l'outil de référence,
clôture `submitPeriod` relayée depuis la demande signée des approbateurs,
vérification sans réseau par `unshare -n` avec les deux vérificateurs,
contrôles 4, 5 et 8 et K-7 à K-9 réussis, cas des calendriers publics en
attente hors `NOORTRACE_RESEAU_PUBLIC=1` ; en attente quand le réseau n'est
pas debout) et
`test/enregistreur-ancrage-exigences.test.js` (`anchoring.ancrage` nul,
configuration refusée, TA-41, classes de clé de chaîne, TA-62, AN-43,
copie WORM d'`ancres/` et de la file, export et réexport, TI-17). Ces
essais prennent le vérificateur Go par `NOORTRACE_VERIFIER_BIN` ; sans lui,
la vérification Go est en attente et la vérification JavaScript faite.

Les corrections de la relecture adversariale de l'étape 5 sont éprouvées
par `test/ancrage-corrections-h1.test.js` (un `describe` par défaut R-C-1 à
R-A-2 et les lectures de la relecture : autorité du serveur interne en
mémoire comme transport, horloge réglable, nœud factice du registre, 1 500
captures mutées, 21 jetons mutés de la relecture en fixture
`test/fixtures/ancrage-h1/`) et `test/enregistreur-ancrage-corrections-h1.test.js`
(R-G-1). L'alignement sur CT-5 révision 0.5 (règles de la révision 0.4) et CT-6 révision 0.5 est éprouvé
par les vecteurs eux-mêmes (24 traces, 41 cas RFC 3161, 21 cas OpenTimestamps)
et, hors traces, par `test/ancrage-planificateur-unites.test.js` (règle de
`point_manquant` depuis le `checkpoint_ts` déclaré, point de clôture sans
minuterie, alertes `contresignature_tardive` et `jeton_anterieur_au_point`
en réussite et en échec).

Les essais du composant (`test/ancrage-composant-*.test.js`) rejouent une
période entière à l'horloge injectée contre des serveurs RFC 3161 du serveur
interne réels sur 127.0.0.1 (interne en HTTP, principal et secours en TLS
mutuel), des calendriers factices locaux (promesses puis chemin complet sur
une chaîne regtest) et le nœud noorcore factice des essais du registre ; les pannes (prestataire
puis retour, registre, calendriers, file pleine, écriture impossible, arrêt
brutal entre `ecrire_file` et l'envoi, CRL révoquée, retrait de
qualification) ; le même parcours contre le réseau de développement réel ; la
fiche et l'épreuve d'acceptation sur deux autorités publiques ; le binaire.

## Exportateur (`src/exportateur.mjs`)

L'exportateur assemble le dossier de CT-1 §11 d'un événement avec ses
ancres (CT-5 §10.1, EX-10.1 à EX-10.5, AN-50 à AN-53) :

- **Point couvrant** (EX-10.2, `choisirPointCouvrant`) : parmi les points de
  la série dont `tree_size > leaf_index`, le premier du rang le plus fort
  (1 : jeton RFC 3161 promu du point, 2 : preuve OpenTimestamps complète du
  point, 3 : ancre du point capturée au registre, 4 : sans ancre), puis le
  plus petit `tree_size`, puis le premier de la série ; `checkpoint_hash`
  est recalculé par `hacherPoint` du noyau et la cohérence du point
  (`coherencePoint`) est contrôlée avant toute écriture. Aucun point
  couvrant : la partie est absente avec sa raison.
- **Partie `points-de-controle.json`** (EX-10.3, `construirePartiePointsDeControle`) :
  le point tel qu'il est dans la série, `checkpoint_hash`, et `anchors`
  (`rfc3161` : jeton promu du point en base64 canonique, `ots` : preuve en
  base64, `registry` : `evm_chain_id`, `contract`, `fingerprint`
  (`empreinteAncre(org, journal, checkpoint_hash)`), `doc_type`, bloc et
  transaction depuis l'index de capture de CT-4 §9.4) ; chaque ancre absente
  est `null`. `JSON.stringify(objet, null, 2)` et un saut de ligne, comme
  les autres parties.
- **Parties réservées** : `jeton-rfc3161.der` et `preuve.ots` du manifeste
  de la période (le `.der` que la dernière ligne d'`acquisitions.ndjson`
  marque `promoted` sans `revoked`, EX-5.8 ; la dernière version de la
  preuve) ; `registre.json`, `certificat-commit.json`, `validateurs.json`
  par `choisirCaptures` et `exporterPartiesRegistre` de `src/registre/`, avec
  `ancre_point_de_controle` quand l'ancre du point couvrant est capturée
  (EX-10.4) ; `entetes-bitcoin.json` de la période copié à côté des parties,
  hors `dossier.json` (EX-6.10, CT-6 §4.3 : entrée à part `--entetes-bitcoin`).
- **`dossier.json`** par `indexerDossier` du noyau sur les octets exacts des
  parties ; les pièces ne sont jamais réencodées (`BORNES_EXPORTATEUR` :
  64 Kio pour un jeton, 256 Kio pour une preuve).
- **Réexport** (EX-10.5, AN-53, `reexportsDus`) : un dossier produit est dû
  quand l'état des ancres de sa période a changé depuis (`etatAncresPeriode` :
  preuve passée `complete`, jeton promu obtenu après coup, ancre capturée,
  clôture relayée, en-têtes écrits) ; le dossier antérieur n'est jamais
  modifié, le nouveau porte un `generated_at` postérieur fixé par l'appelant.
  Pour un même événement, seul le dossier le plus récent compte.
- Aucune horloge, aucun aléa : `generated_at` vient de l'appelant.

## Branchement dans l'enregistreur

`paquets/enregistreur/src/ancrage-demon.mjs` (`preparerAncrage`,
`BranchementAncrage`) relie le composant au démon `noortrace` :

1. **Démarrage** (CT-2 §15.4) : quand `anchoring.ancrage` n'est pas `null`,
   le document `ancrage-v0` est lu en JSON strict, les références de
   secrets des prestataires (`/rfc3161/providers/<i>/auth/secret`) et de la
   source d'en-têtes (`/opentimestamps/headers_source/auth`) sont résolues
   par le résolveur de secrets de l'enregistreur (`env`, `file`, `vault`,
   CT-2 §15.2) vers `contexte.secrets`, la clé de chaîne de
   `anchoring.registry.chain_key` est construite (classe D par
   `SignataireChaineFichier`, adresse confrontée à `address`), le manifeste
   d'instance du registre est lu. Une clé de chaîne de classe A, B ou C
   refuse le démarrage du démon (`demarrage_refuse : ancrage : classe_cle_chaine`,
   code 2, message qui nomme l'étape 7). Tout autre défaut (document
   illisible, AN-1, secret non résolu, manifeste absent) laisse le démon
   démarrer : `anchoring_not_started` est consigné avec la raison, et chaque
   remise est consignée `anchor_pending` (CT-5 EX-4.8, CT-2 §14.2).
2. **Contexte** : `org_id`, `journal_id`, l'époque du bail, `storage.root`,
   `clePublique` par le signataire du cœur, `lireSerie` (série
   `points/periode-<P>.ndjson` relue sans la modifier), `lireHashesPeriode`
   (hashes des événements de la période relus dans les segments, dans
   l'ordre des `seq`), `listerPeriodes` (manifestes et signatures durables),
   `listerPoints`, `cleChaine`, `instance`, `signaturesCloture` (lecture
   F2-3). Les envois et captures du registre vont sous
   `<journal>/registre/`.
3. **Horloge, aléa, journal, métriques** : l'horloge de l'enregistreur
   (CT-2 §7.4) étendue de `programmer` ; `crypto.randomBytes` ; le
   `JournalExploitation` du cœur (composant `ancrage`) ; `/metrics` de la
   supervision expose les métriques d'EX-8.15 avec celles du cœur.
4. **Attache** : `Coeur.demarrer({ ancrage })` ; le composant est démarré
   après l'écrivain (`anchoring_attached`) et arrêté après lui ;
   `remettrePoint`/`remettreCloture` rendent la main sans attendre le réseau
   (EX-4.12) ; `noortrace-ctl reload` recharge le document avec la politique
   (`recharger`) ; `noortrace-ctl ancrage etat|metriques|retirer-qualification <id>`.
5. **Export** : `Coeur.exporterDossier` passe par l'exportateur quand le
   composant est démarré ; `Coeur.reexportsDus` liste les dossiers dus.
6. **Copie WORM** (EX-5.15, EX-8.14) : les fichiers d'`ancres/` et de la
   file sont copiés par le service de copies de l'enregistreur (lecture F2-6).

## Lectures

Passages lus et tranchés par le texte (section, citation, vecteur, lecture),
par lot. Chaque lecture est vérifiée par les vecteurs quand ils la couvrent.

### Lot A (client RFC 3161)

1. **Statuts des vérifications.** CT-6 EX-6.1 : `reussi`, `echoue`,
   `non_execute` ; `attendu.json` emploie `echoue`. Retenu partout.
2. **`checks_passed` d'une réponse en échec aux étapes 3 à 5.** EX-5.10 dit
   « s'arrête à la première étape en échec », mais `granted-autre-empreinte`
   (`checks_passed` sans T-2) et `granted-politique-hors-liste` (sans T-7)
   montrent T-1 à T-9 évaluées en entier : l'arrêt porte sur l'issue et le
   code, les T- sont calculées pour `checks_passed` et l'enregistrement.
3. **Étape 6 quand une T- est `non_execute` pour une raison admise**
   (`hors_perimetre_version`, unité Ed25519) : un jeton dont la signature
   n'est pas vérifiée n'établit aucune date (EX-9.24) ; `echec_permanente`,
   `verification_T-5`, jeton conservé comme pièce.
4. **Jeton dont T-1 échoue** : `verification_T-1`, permanente,
   `imprint_matches` et `nonce_in_response` nuls.
5. **Code des erreurs de transport** : `erreur_transport` et `delai`, les
   valeurs du champ `transport` du schéma, servent aussi d'`error_code`.
6. **`Retry-After`** : EX-8.9 (plus précise qu'EX-5.12) : suivi sur 429 et
   503 seulement, les autres suivent `retry`.
7. **`accuracy_s` du schéma** : arrondi par excès de la précision en
   secondes ; `upper_bound` de l'enregistrement garde la milliseconde.
8. **Numéro de série rapporté** : octets de valeur de l'`INTEGER` sans zéros
   de tête, hexadécimal `0x` (`0x01` dans les faits de CT-6).
9. **T-9, règle 3, quand T-4 n'a pas réussi** : `non_execute` avec la raison
   héritée de T-4 si `tsa` est un `directoryName` et que les autres règles
   tiennent (`t4-ess-autre-certificat` : `prerequis_en_echec`).
10. **T-7 et ses trois prérequis** : un prérequis `echoue` donne
    `prerequis_en_echec`, sinon la raison du premier `non_execute`.
11. **Jeton promu (EX-5.8)** : le premier enregistrement `obtenue` d'un objet
    porte `promoted` ; `choisirPromu` applique la règle complète quand
    plusieurs jetons sont reçus avant qu'une demande passe `obtenue`.
12. **Écriture des pièces** : requête, réponse, jeton, puis la ligne
    d'acquisition ; le `.tsr` n'est écrit que pour une réponse
    `application/timestamp-reply` de statut 200 (réponse d'erreur comprise) ;
    un jeton en échec (T-6, empreinte, nonce, politique) est conservé.
13. **Dates des certificats d'ancre** (EX-9.13) : non comparées à `genTime`,
    sauf quand l'ancre désigne l'unité elle-même.
14. **T-4, `issuerSerial`** : contrôlé sur le premier `ESSCertID(v2)` ; un
    identifiant illisible met T-4 en échec, non T-1.
15. **CRL du certificat de l'autorité** (EX-9.16) : seules celles du fichier
    d'ancres (ou capturées par CT-5) sont consultées, sans exiger leur
    signature ; celles du jeton ne le sont pas.

### Lot B (client OpenTimestamps)

1. **O-5 sans point de contrôle de réviseur (EX-6.9)** : le premier en-tête
   du fichier joue le rôle du point de contrôle (c = s) ; règles 1, 2, 4, 5,
   6 d'EX-10.9 ; la règle 3 n'a pas d'objet ; avec `ancre`, EX-10.9 telle
   qu'écrite (vingt cas de CT-6).
2. **O-4 quand toutes les attestations Bitcoin sont hors profil** :
   `non_execute`, `hors_perimetre_version` (EX-10.12) ; une hauteur hors du
   fichier donne `ancre_absente`.
3. **Avertissements** : AV-O-2 pour toute attestation en attente, inconnue
   ou hors profil ; AV-O-3 seulement si O-5 a été exécutée.
4. **Doublons sous un même nœud** : refusés (`doublon`, O-1) : un tel fichier
   n'a pas de forme canonique (esprit d'EX-10.2).
5. **`entetes-bitcoin.json` jamais réécrit** : création exclusive ; écrit par
   le composant une fois toutes les preuves de la période complètes.
6. **Réponse de calendrier (EX-6.2, étape 3)** : refusée si illisible, hors
   profil, hors bornes ou sans attestation ; l'URI de l'attestation n'est pas
   comparée à l'URL de soumission (un agrégateur relaie vers un calendrier
   d'une autre URI) : `upgrade.whitelist` porte les URI des **calendriers**.
7. **Mise à niveau sans source d'en-têtes** : O-1 et O-3 suffisent ; des
   en-têtes qui ne couvrent pas la hauteur donnent `en_tetes_insuffisants`
   avec admission ; O-4 ou O-5 en échec refuse.
8. **Exemple de CT-6 §10.3** : l'en-tête du bloc 358391 satisfait sa cible ;
   `racine(h)` est lue aux octets 36 à 67 sans inversion.
9. **Règle 5 d'EX-10.9** : `Δ` sur 2015 intervalles, comme Bitcoin Core
   (confronté au réajustement de la hauteur 32256) ; `non_execute`,
   `ancre_absente` quand l'en-tête 2016 hauteurs plus bas manque.

### Lot C (planificateur)

1. **Ordre des actions à un même instant** (EX-8.16) : ouvertures
   d'échéances, puis `point_manquant`, puis minuteries dans l'ordre de la
   file ; à l'admission d'un point : file pleine, ancre au registre, échéances
   et jeton, `ots_point`, envoi du jeton si l'ancre est déjà obtenue.
2. **`inclusion_late` à l'inclusion** : mesurée depuis `created_at` de la
   demande d'ancre, signalée une fois.
3. **`point_manquant`** : d'abord lue « à 2 c_K après le dernier point admis
   ou le démarrage ; jamais après la clôture » ; CT-5 révision 0.4 (EX-4.1,
   8.9) tranche autrement : voir la lecture 1 de l'alignement sur les textes
   révisés, ci-dessous (délai compté depuis le `checkpoint_ts` déclaré du
   dernier point admis, point de clôture sans minuterie).
4. **Taille représentée des captures** : 4 096 (`TAILLE_CAPTURE_REPRESENTEE`)
   sauf `capture_size` dans l'entrée.
5. **Ordre de la file** : `queue_after` et `file()` triés par (`created_at`,
   `id`) ; `queue_before` et `*.avant.ndjson` dans l'ordre d'apparition.
6. **`auth` `aucune` et `http://`** (EX-5.5, règle 4) : admis dans tous les
   profils pour le seul rôle `interne` vers une adresse locale ; refusés
   partout ailleurs. Conséquence (F1) : une autorité publique sans compte
   n'est pas configurable comme prestataire ; sa fiche et son épreuve
   d'acceptation se jouent quand même (`composant.fiche`, binaire).
7. **Exemple d'EX-4.8 en production** : refusé par la seule règle 1 quand le
   c_K de l'enregistreur n'est pas connu ; `qualified` est déclaratif.
8. **Échéances déjà passées** : ouvertes sans action `echeance` quand la
   période devient connue, rendues avec le premier jeton de point.
9. **Relève après redémarrage** : non réarmée depuis les tentatives relues ;
   le délai repart de la première tentative après le redémarrage.
10. **Nonce OTS** : dérivé une fois par demande ; sa persistance revient au
    composant (`ots/<objet>.nonce`).
11. **`arret`** : les minuteries échues à l'instant de l'arrêt sont servies.
12. **Noms des règles d'admission** (AN-3) : `format`, `period_start`,
    `signature`, `chainage`, `monotonie`, `racine`, `last_seq`, `last_hash`.
13. **Règle 8 (PEM)** : forme d'un certificat (bornes et étiquettes) ; la
    lecture complète est celle du lot A.
14. **Point déjà connu** (EX-8.5 règle 2) : `anchor_duplicate_ignored` par
    demande existante, sans `checkpoint_not_anchored`.
15. **`provider_role` `aucun`** : échéances closes `sans_objet`
    (`prestataire_aucun`) ; l'`ots_point` reste soumis.

### Lot D (registre)

1. **`request_id` d'un renvoi ou d'un remplacement** : retenu en mémoire par
   l'`Envoyeur` ; après un redémarrage, l'appelant le passe (le composant le
   retrouve par l'empreinte de la transaction).
2. **Ancre refusée à l'inclusion (`status 0x0`)** : l'état est relu par
   `lookup` ; `empreinte_squattee` si un autre émetteur a l'empreinte, sinon
   `transaction_annulee` ; le nonce est consommé.
3. **Validateurs en avance et en retard** : les lectures qui dépendent d'une
   transaction incluse sont faites sur le point qui a servi la capture.
4. **Envoi refusé par tous les points** : issue `ecartee`, échec
   `transaction_refusee` (ou `noeud_injoignable`).
5. **`deja_fait` à l'ancre** : `inclusion_registre` de la capture déjà faite,
   sinon échec `deja_fait`.
6. **CP-1 et `noor_txindexStatus`** : lue, `noeud_suiveur` si elle manque.
7. **Rôle d'une capture de point** : index au rôle `ancre` ; le `docType` du
   journal fait l'entrée `ancre_point_de_controle` à l'export.
8. **Lignes de certificat (CT-6 EX-11.6)** : membres comparés sans la casse,
   dernière occurrence retenue, `Type` d'un precommit toléré avec AV-R-2.
9. **Arguments du constructeur de `CuratorSetRegistry`** : comparés au compte
   administrateur dont l'intervalle contient le bloc de déploiement.
10. **RG-19 sans manifeste de production** : `evidence` nul admis hors
    production.

### Lot E (serveur interne)

1. **Bit `unacceptedPolicy`** : 15 (RFC 3161 §2.4.2, vecteur
   `rejet-unacceptedPolicy.tsr`).
2. **Nonce et bornes du client** : le serveur sert une requête sans nonce, à
   nonce 0 ou de plus de 64 bits (les bornes d'EX-5.3 sont celles du client) ;
   il refuse un encodage non DER (`badDataFormat`).
3. **Validité de l'unité à l'émission** : `systemFailure` (transitoire pour
   le client) quand `genTime` sort de la validité.
4. **`accuracy` 0** : admise, fait refuser tout écart mesuré non nul.
5. **Écart d'horloge absent** : vaut 0 ; une valeur non finie fait cesser
   l'émission (`timeNotAvailable`).
6. **`CA:FALSE`** : `basicConstraints` vide non critique (`cA` DEFAULT omis).
7. **Un seul émetteur par clé** : verrou `O_EXCL` et pid d'un répertoire
   local ; un verrou périmé est repris.

### Lot F1 (assemblage)

1. **Entrées que le schéma ne porte pas** (règle 1 d'`INTERFACES.md`).
   EX-5.9 (retrait de `qualified`) et EX-5.10 étape 10 / EX-8.3 (révocation
   constatée : `obtenue → a_reprendre`) sont normatives pour le composant,
   mais « aucune entrée du planificateur ne porte le retrait » et l'annexe
   A.3 dit qu'aucune trace ne porte la révocation. Lecture : deux méthodes
   du planificateur, `relever` et `revoquer`, hors `traiter`, qui rendent
   leurs actions comme une entrée ; les traces ne changent pas.
2. **EX-9.5, « encore `a_envoyer` »**. Pendant une indisponibilité, le lot D
   rend `noeud_injoignable` sans qu'aucune transaction entre en mempool, et le
   lot C passait l'ancre `a_reprendre` puis la renvoyait au retour, une par
   point : « les demandes … ne sont pas toutes envoyées : seule celle du point
   admis le plus récent part » n'était pas tenu. Lecture : une ancre
   `a_reprendre` dont aucune tentative n'a été admise par un nœud est
   « encore à envoyer » et passe `remplacee` à l'admission d'un point plus
   récent ; une ancre dont une transaction est partie (`recu_absent`) suit
   CT-4 §8.6. Défaut du lot C corrigé (`ancreEncoreAEnvoyer`), traces inchangées,
   essai « registre injoignable » du composant.
3. **Révocation et `promoted` (EX-5.8)**. `acquisitions.ndjson` est en ajout
   seul et `promoted` « ne change qu'à une révocation constatée » : la T-10
   différée ajoute une ligne pour la tentative promue (`checks.T-10`,
   `revoked`, `files.crls`, `revocation`), et `DepotAncres.promu` /
   `dejaPromu` lisent le **dernier état de chaque `attempt_id`**
   (`dernieresAcquisitions`). Défaut du lot A corrigé (l'ancienne lecture
   ignorait la ligne de révocation) ; le nouveau jeton du secours est alors
   promu, l'ancien conservé.
4. **Un `.crl.pem` par tentative** (EX-5.14 : « une par certificat du
   chemin »). Le nom de fichier d'EX-5.14 ne porte pas d'indice de certificat :
   toutes les CRL du chemin sont écrites dans le seul fichier
   `<objet>-<provider_id>-<attempt_id>.crl.pem`, un bloc PEM par certificat,
   dans l'ordre du chemin.
5. **Nonce OpenTimestamps durable** (EX-6.2 : rejeu avec le même engagement
   après redémarrage). `$defs/tentative.nonce` est un `hex8` (RFC 3161) : le
   nonce de 16 octets n'a pas de place dans le schéma ; il est écrit dans
   `ots/<objet>.nonce` du répertoire de la période (création exclusive), à
   côté des preuves, et relu avant tout tirage.
6. **Étape 9 impossible** (EX-5.12 : « rejouer l'écriture ; la réponse reçue
   n'est pas renvoyée »). Le composant garde le résultat d'`acquerir` en
   mémoire, consigne `anchor_piece_write_failed` et l'alerte `file_perdue`,
   et rejoue l'écriture des pièces à chaque tic avant d'injecter la réponse ;
   aucune nouvelle requête n'est envoyée pour cela.
7. **Clôture `submitPeriod`** (CT-4 §8.2, pas 3 à 5). Le planificateur n'a
   pas de demande pour la clôture et les signatures des approbateurs viennent
   d'un outil de signature hors du composant : après l'inclusion et la
   capture de `ancre_registre_periode` (EX-8.4), le composant appelle
   `Envoyeur.clore` avec les signatures que `contexte.signaturesCloture`
   fournit ; sans cette fonction, il consigne `period_close_delegated` et
   laisse la clôture à l'exploitation. Les échecs sont repris au tic à la
   cadence de `retry` (`registry_pending`) ; un redémarrage reprend les
   clôtures des ancres de période `obtenue` (idempotence de `clore`).
8. **Autorité publique sans compte** (EX-5.5, règle 4 d'AN-1 : `auth`
   `aucune` pour le seul rôle `interne`). SwissSign et DFN répondent sans
   compte mais ne sont pas configurables comme prestataires ; leur fiche et
   leur épreuve d'acceptation sont jouées par `composant.fiche` (qui ne dépend
   pas du démarrage) et par le binaire.
9. **`anchor_retry` d'EX-8.15**. Le planificateur ne la consigne que pour le
   registre ; le composant la consigne pour chaque reprise programmée d'une
   demande RFC 3161 ou OpenTimestamps (`programmer` de raison `backoff`,
   `retry_after`, `immediat`).
10. **Attribution de `attempt_id`**. Le planificateur dérive
    `correlation_id = <kind>:<16 hex>:<n>` (annexe A.2) ; le composant le
    passe à `acquerir` comme `attempt_id`, de sorte que la file, l'en-tête de
    corrélation et les noms des pièces portent la même valeur.
11. **Deux lecteurs DER** (règle 8 d'`INTERFACES.md`). Le lecteur du lot A
    (`der.mjs`) et celui du lot E (`der-lecture.mjs`) sont gardés : E lit ses
    requêtes et ses certificats avec sa propre API (`lireUnique`,
    `lireSuite`, `exiger`) et ses refus nommés par bit `PKIFailureInfo` en
    dépendent ; les six réponses `granted-*.tsr` sont reproduites octet pour
    octet. Les rapprocher exposerait E à une régression sans gain fonctionnel ;
    c'est un chantier d'entretien, pas d'assemblage.
12. **Secret du binaire `fiche --epreuve`**. L'épreuve d'EX-11.4 exige le
    secret d'accès : le binaire résout `{ env }` et `{ file }` (CT-2 §15.2)
    lui-même, hors de `src/`, et n'affiche jamais la valeur ; un emplacement
    `vault` n'est pas résolu par cet outil.

### Lot F2 (exportateur, branchement)

1. **Répertoire des dépôts sans `0x`** (CT-2 EX-12.1 : « `storage.root/<org_id>/<journal_id>/`,
   hexadécimal sans `0x` » ; CT-5 EX-5.14 écrit `<racine>/<org_id>/<journal_id>/ancres/`).
   Les dépôts des lots A et B préfixaient `0x` : corrigés (`DepotAncres`,
   `DepotOts`), leurs essais aussi, pour que `ancres/` soit sous le
   répertoire du journal de l'enregistreur et dans le périmètre de sa copie
   WORM (EX-12.27).
2. **`entetes-bitcoin.json` « à côté »** (EX-6.10 ; CT-6 §4.3 : « entrée à
   part, `--entetes-bitcoin` » ; CT-1 §11 : `dossier.json` énumère les treize
   parties). Le fichier est écrit dans le répertoire du dossier, sans entrée
   dans `dossier.json` ; les deux vérificateurs le prennent par leur option
   et acceptent le dossier ainsi produit (contrôle 5 `reussi` quand la preuve
   est complète, `non_execute` sinon).
3. **`signaturesCloture`** (CT-4 §8.2 pas 3 à 5 ; lecture 7 du lot F1 :
   « signatures des approbateurs … d'un outil de signature hors du
   composant »). Le démon relaie `submitPeriod` quand l'exploitant a déposé
   la demande signée au seuil (forme `demande_signature` de CT-4, `operation`
   `cloture`, vérifiée par `verifierDemande` : OP-6, OP-7) sous
   `<journal>/registre/demande-cloture-<period_hash>.json` ; une demande
   d'une autre période ou invalide est consignée `period_close_request_refused`.
   Sans demande, `signaturesCloture` rend `null` et le composant consigne
   `period_close_delegated` (`reason: signatures_en_attente`) et revient au
   tic de `retry.max_ms`, sans alerte : la clôture attend l'exploitant,
   l'ancre de la période est déjà capturée. `#clore` du composant a été
   complété pour ce retour `null` (il attendait un objet).
4. **Manifeste d'instance** (CT-4 §4.8 ; CT-2 §15 n'a pas de clé pour
   lui). Lu dans `instance-registre.json` à côté du document `ancrage-v0`
   (`evm_chain_id`, `bft_chain_id`, `contracts` nommés ou tableau
   `{ name, address }`, `validator_sets`, `fees`) ; absent avec le registre
   activé : `anchoring_not_started` `instance_registre_absente`. À inscrire
   dans CT-2 : une clé `anchoring.registry.instance` (chemin du manifeste).
5. **Profil du composant** (CT-5 §4.4 : profils `production`, `developpement`,
   `test` ; CT-2 `recorder.environment` : `production | developpement`). Le
   profil est `production` si et seulement si `recorder.environment` l'est,
   `developpement` sinon ; le profil `test` de CT-5 n'est pas atteignable
   depuis la configuration du démon.
6. **Copie WORM d'`ancres/` et de la file** (EX-5.15, EX-8.14 ; CT-2 EX-12.27,
   lecture 93 de l'enregistreur : « un fichier modifié après sa copie n'est
   pas recopié »). Un fichier n'est copié qu'une fois fermé : les pièces
   (`rfc3161/*.tsq|.tsr|.der|.crl.pem`, `ots/*.ots|.nonce`, `entetes-bitcoin.json`)
   dès leur écriture ; `acquisitions.ndjson` (ajout seul) quand le manifeste
   de la période existe et que la T-10 différée de chaque jeton promu est
   décidée (ou `rfc3161.crl_capture.enabled` faux) ; `file-<epoque>.ndjson`
   quand son époque est inférieure à celle de l'écrivain. `queue.path` est à
   placer sous le répertoire du journal (`<journal>/ancres/file`) pour être
   dans le périmètre ; les sous-répertoires `envoi-*`, `capture-*` du
   registre suivent la règle des fichiers fermés sous `registre/`.
7. **Clé de chaîne de classe A à C** (CT-2 EX-11.19). Le démon refuse de
   démarrer (code 2) avec un message qui nomme le reste : seule la classe D
   est servie, les classes A à C sont l'étape 7 ; un refus silencieux ou une
   clé de classe D « de secours » auraient caché un écart de configuration.
8. **Rotation d'urgence au registre** (`registre_non_branche` de
   `Coeur.rotationUrgence`). Inchangée : le lot D encode les appels
   d'inscription et de révocation (`encoderRegisterRecorder`,
   condensés OP-6/OP-7) mais son `Envoyeur` n'envoie que `anchorCheckpoint`,
   `submitPeriod` et `clore`, et CT-4 §7 fait signer la révocation et la
   nouvelle inscription par les approbateurs au seuil (demandes
   `demande_signature`) : brancher la rotation au registre exige l'outil de
   signature des approbateurs et les envois `revokeRecorder`,
   `registerRecorder`, hors du lot. Le refus reste nommé dans les restes de
   l'enregistreur.
9. **Commande `exporter` de l'outil `noortrace-ancrage`** (annoncée par F1).
   Non écrite : les sept parties de CT-1 (événement, voisins, chemin,
   manifeste, clés, approbations) se lisent dans les segments de
   l'enregistreur, que l'outil du composant ne connaît pas ; l'export est
   servi par `Coeur.exporterDossier` du démon et par la fonction
   `exporterDossier` du paquet. Un outil hors démon relèverait de
   l'exportateur complet de CT-6.
10. **Réexport dû une fois** (EX-10.5 : « un dossier remis dont la preuve
    était en attente est réexporté »). Pour un même événement, `reexportsDus`
    ne compare que le dossier le plus récent à l'état courant : le dossier
    remplacé n'est plus dû (il n'est pas modifié non plus).
11. **Nœud factice du lot D et R-9** (CT-4 §9.6 : `publishedAt` du reçu
    égal à `block.timestamp`). La fixture `test/fixtures/ancrage-registre/noeud-factice.mjs`
    incrémentait l'horodatage après l'exécution du bloc : le reçu portait
    l'instant du bloc précédent et le vérificateur Go refusait R-9 sur un
    dossier réel ; corrigé dans la fixture, essais du lot D inchangés.
12. **Horloge partagée avec le démon réel** (TE-12). Le démon enfant
    (`test/fixtures/enregistreur-ancrage/demon.mjs`) reçoit l'horloge
    hybride des essais par `principal(argv, { horloge })` et des commandes
    JSON sur son entrée standard (`avancer`, `evenement`, `exporter`,
    `reexports`, `etat`, `journal`, `arreter`) ; `superviserProcessus`
    (signaux, `noortrace-ctl`) est exporté de `cli.mjs` pour lui. Le démon de
    production n'a rien de plus : `io.horloge` est facultatif.

### Lot G2 (épreuves CT-9 de l'étape 5 et campagne de mesures)

1. **Rapport de mesure hors du système de référence** (CT-9 EX-11.2 ; schéma
   `plan-de-tests-v0#/$defs/rapport_mesure` : `system.reference` faux ⇒
   `counts_for_targets` faux ⇒ `met` null et `excluded_reason` sur chaque
   ligne). La consigne du lot demandait `counts_for_targets` vrai pour les
   cibles mesurables de TM-14 : le texte et le schéma l'interdisent sur cette
   machine (virtuelle, disque virtuel). Le rapport
   `spec/vecteurs/ct-9/mesures/rapport-2026-11-09-ancrage.json` porte donc
   `met` null partout, et ses notes disent, ligne par ligne, si la cible est
   tenue en valeur.
2. **TE-12 réelle : journal inscrit par l'épreuve** (CT-4 §7.7, §8.2, OP-10 ;
   reste F2 « variante réelle avec un journal inscrit par le démon
   lui-même »). Le journal que le parcours de référence inscrit a déjà une
   période close au registre : une clôture relayée par le démon devrait
   enchaîner `first_seq` sur son `last_seq`, ce qu'un démon au stockage neuf
   ne peut pas faire. L'épreuve inscrit donc un journal neuf (clé Ed25519 et
   clé de chaîne de classe D neuves) sous l'organisation du parcours, par
   l'outil de référence exécuté comme une boîte noire (`condense inscription`,
   `signer` par deux approbateurs du parcours, `approvisionner` par la
   trésorerie de développement, `inscrire-cle` ; `inscrireJournal` de
   `test/fixtures/enregistreur-ancrage/outils.mjs`), et la première clôture
   de ce journal n'a aucune continuité à tenir. La demande de clôture est
   construite par `demandeClotureParcours` (forme `demande_signature`,
   `signer_set` de l'inscription, signatures des approbateurs rangées par
   adresse) et déposée sous `<journal>/registre/demande-cloture-<period_hash>.json`
   (lecture F2-3). Deux démons qui partagent une clé de chaîne se
   disputeraient les nonces : chaque épreuve et chaque campagne a la sienne.
3. **`latestPeriodOf`** (CT-4 OP-10) rend l'identifiant de la dernière
   période du journal dans la suite du contrat (compteur de toutes les
   périodes), non un rang par journal : l'épreuve lit la période par cet
   identifiant et confronte son `periodHash`.
4. **`min_interval_ms` sur une autorité publique** (TI-16 ; EX-5.5, EX-8.7 ;
   lecture F1-8 : une autorité sans compte n'est configurable que dans le
   rôle `interne` vers une adresse locale). L'autorité publique est servie au
   composant par un relais HTTP local (`http://127.0.0.1`, rôle `interne`)
   qui transmet la requête telle quelle en HTTPS et consigne l'instant de
   réception ; l'intervalle se mesure dans ce journal et dans `sent_at`
   d'`acquisitions.ndjson` (`anchor_retry` de raison `backoff` pour la
   seconde requête). Le composant ne sait pas qu'un prestataire est derrière
   le relais : c'est l'épreuve du mécanisme sur un prestataire réel.
5. **T-10 sur les CRL publiées des autorités publiques** (EX-5.10 étape 10 ;
   CT-6 EX-13.12). Au moment de l'acquisition, les CRL publiées de SwissSign
   et de DFN ont un `thisUpdate` antérieur à `genTime` : `capturerCrls` rend
   l'erreur « thisUpdate antérieur à genTime » (ce que le composant consigne
   `crl_indisponible` et réessaie), et `verifierRevocation` rend
   `non_execute`/`ancre_absente`. L'épreuve le dit dans son titre ; T-10
   réussirait avec une CRL postérieure à `genTime` pour chaque certificat
   du chemin.
6. **JS-2 de CT-7 §6.1** (« aucune ligne propre » pour l'arrêt). Le démon
   consigne une ligne `shutdown` dans le journal d'exploitation (hors
   chaîne), absente de la liste d'EX-17.2 de CT-2 et proposée par PA-3 ; la
   chaîne ne porte aucun événement d'arrêt, comme la table le dit. TE-14
   constate les deux et ne tient pas la ligne `shutdown` pour un écart : elle
   n'est pas dans la chaîne (CT-7 EX-6.3 porte sur les propositions qui
   touchent la chaîne).
7. **`keep_files` du journal d'exploitation** (CT-2 EX-9.7 : « conservé
   `logging.keep_files` fichiers »). Lecture : `keep_files` fichiers tournés
   (`<chemin>.1` à `<chemin>.keep_files`) à côté du fichier courant ; le plus
   ancien est supprimé à chaque rotation ; c'est ce que TE-14 vérifie.
8. **`config_reloaded` sans `sha256`** (CT-2 EX-18.6 : « au démarrage et à
   chaque rechargement, le démon consigne le `sha256` des octets du document
   de configuration (`startup`, `config_reloaded`) et le `policy_sha256` »).
   Le cœur ne portait que `policy_version` : plus petit correctif dans
   `paquets/enregistreur/src/coeur.mjs` (`config_sha256`, `policy_sha256`),
   éprouvé par TE-14 (JS-7).
9. **Mesures accélérées** (CT-9 EX-11.5). TM-17 (débit du planificateur,
   journaux par instance, file en régime de panne) est joué à l'horloge
   réglable du composant (une heure simulée) : les lignes le disent dans
   `conditions`, ne comptent pour aucune cible (TM-17 n'en a pas) et sont
   publiées. Tout le reste (TM-11 à TM-14, TM-19, TM-41, TM-42) est mesuré
   en temps réel sur une période complète par configuration (porte 2 :
   `c_T` 60 s ; défaut : `c_T` 300 s), les deux campagnes en parallèle sur
   deux journaux inscrits distincts.
10. **TM-13 et la porte 2**. TM-13 fixe `c_T = 300 s` : la ligne `p3_d_jeton`
    vient de la configuration par défaut ; la ligne `p3_d_jeton_porte_2`
    (nom propre, EX-11.11) publie le même délai avec `c_T = 60 s` à titre de
    comparaison, hors de la condition de l'entrée.
11. **TM-14 et le prestataire qualifié**. Aucun prestataire qualifié réel
    n'est sous contrat : le principal de la campagne est le serveur interne
    de référence (EX-7.4) DÉCLARÉ qualifié par l'instantané d'exemple d'EX-4.8
    dans la configuration et dans le fichier d'ancres de test ; T-11 réussit
    par cette déclaration seulement, la ligne `p4_cloture` le dit.
12. **TM-16 sur le support réel avec `ancres/`** (CT-5 P-6 ; lecture F2-6).
    `acquisitions.ndjson` n'est copié qu'une fois fermé (période close et
    T-10 différée décidée) : la mesure d'`ancres/` sur LocalStack se fait
    après un balayage des copies (`worm balayer`) ; la série de la période
    courante, fichier ouvert, n'entre pas dans la mesure.
13. **Mémoire du démon pendant les exports** (EX-10.5 ; collecte porte 2 du
    9 novembre). Après 2 799 exports d'une période à `c_T` 60 s, le tas du
    démon s'épuisait (`exporter` sans réponse, arrêt sur manque de mémoire).
    Cause, établie par deux instantanés du tas d'un démon réel : chaque
    export gardait son résumé pour `reexportsDus` dans une liste sans fin, et
    les chaînes du résumé (SHA-256 du jeton, état de la preuve) étaient des
    tranches du texte entier d'`acquisitions.ndjson` relu par l'analyseur
    JSON ; le moteur garde ce texte tant qu'une tranche vit, soit un fichier
    entier (375 Ko à `c_T` 60 s) par export. L'index des nonces gardait de
    même le texte de chaque fichier d'acquisitions lu. Corrections :
    `lireAcquisitions` rend des `copieAutonome` (chaînes recopiées),
    `exporterDossier` rend un `resume` autonome, et le branchement garde le
    dernier résumé de chaque événement (`Map` de clé `<hash>:<seq>`, le plus
    récent par `generated_at`, la règle même de `reexportsDus`). Essais :
    `test/ancrage-exportateur.test.js` (« mémoire » : 40 résumés et l'index
    des nonces sur un fichier de 3 Mo retenaient 487 Mo avant, moins de
    16 Mio après) et `test/enregistreur-ancrage-exigences.test.js` (un seul
    résumé par événement après trois exports).
14. **Nonce lu sur un validateur en retard** (CT-4 EX-8.14 : « le nonce est
    `eth_getTransactionCount(expéditeur, "latest")` », sans dire auprès de
    quel validateur). Sur le réseau de développement, un validateur a encore,
    pendant environ une seconde après une inclusion, l'état d'avant le bloc.
    L'`Envoyeur` lisait le nonce sur le premier point qui répond : juste
    après une inclusion, il signait parfois le nonce de la transaction déjà
    incluse, refusée partout (« nonce too low » par les validateurs à jour,
    « replacement transaction underpriced » par celui qui la tenait encore en
    mempool) ; le planificateur la reprenait (`transaction_refusee` est une
    ancre encore à envoyer), mais l'essai réseau du registre échouait.
    Lecture retenue : le plus grand nonce `latest` des points qui répondent,
    qui reste la lettre d'EX-8.14. Essai : `test/ancrage-registre-envoyeur.test.js`
    (« nonce d'EX-8.14 » : premier point en retard d'une transaction ; avant,
    `transaction_refusee`, « nonce too low » sur les quatre points ; après,
    inclusion au nonce 1). Les essais du réseau attendent de plus que chaque
    validateur ait le bloc avant de relire l'état sur le premier point
    (`tousAuBloc`, déjà employé pour l'empreinte prise), ce qui faisait
    échouer la course à l'inclusion et la relecture de la clôture.
15. **Ancre à reprendre pendant l'envoi d'une autre ancre** (EX-9.4 : une
    ancre qui attend son tour « part au reçu (ou au refus) de l'ancre en
    vol » ; EX-8.10). Quand la minuterie de reprise d'une ancre
    `a_reprendre` tombait pendant l'envoi d'une autre ancre de la même clé
    de chaîne, elle était programmée `attente_nonce` sans minuterie, mais au
    reçu de l'ancre en vol le planificateur ne choisissait que les ancres
    `a_envoyer` : l'ancre de la période restait `a_reprendre` sans fin, son
    jeton en `attente_registre` (constaté par l'essai JS-11 de
    `test/enregistreur-journal-soi.test.js`, qui échouait une fois sur deux
    selon l'instant de la reprise). Correction : au reçu ou au refus, une
    ancre `a_reprendre` dont l'échéance est passée est candidate au même
    titre qu'une ancre `a_envoyer` (périodes d'abord, puis points par
    `checkpoint_ts`) ; une ancre dont l'échéance n'est pas venue attend sa
    minuterie. Essai : « EX-9.4, EX-8.10 : une ancre à reprendre … » de
    `test/ancrage-planificateur-unites.test.js` (avant : deux envois, l'ancre
    de la période jamais renvoyée ; après : renvoi au reçu de l'ancre du
    point) ; JS-11 passe quatre fois sur quatre. Les traces de CT-5
    rejouées sont inchangées.
16. **`Content-Length` de la soumission OpenTimestamps** (EX-6.2 : « `POST
    <url>/digest`, corps = les 32 octets, en-tête `Accept` »). Le transport
    par défaut posait `Content-Length` à la main en plus du corps
    `Uint8Array` ; `fetch` le calcule déjà. Selon la version d'undici
    embarquée par Node, l'en-tête partait deux fois, et un serveur qui reçoit
    deux `Content-Length` répond `400` (le serveur HTTP de Node le fait avant
    tout gestionnaire) : sur l'intégration continue (Node 22 plus récent que
    celui de la machine de construction), aucune soumission n'atteignait les
    calendriers factices, `calendriers_insuffisants` à chaque essai ; un vrai
    calendrier derrière un frontal strict aurait fait de même. Lecture
    retenue : l'en-tête n'est pas posé, `fetch` l'écrit une fois. Essai :
    « POST : méthode, Accept, corps de 32 octets sans Content-Length posé à
    la main … » de `test/ancrage-ots-calendriers.test.js` ; constat du
    serveur de Node (deux `Content-Length` : `400 Bad Request`, gestionnaire
    jamais appelé) reproduit sur la machine de construction.

### Lot H1 (corrections après la relecture adversariale de l'étape 5)

1. **`Retry-After` (EX-8.9, règle révisée).** L'attente après une erreur
   transitoire vaut `Retry-After` quand la réponse 429 ou 503 en porte un,
   **bornée** : au moins `retry.initial_ms`, au plus `retry.max_ms` ; la
   valeur consignée `retry_after_s` est celle lue, plafonnée à 604 800 (borne
   de `$defs/tentative`) ; sur 408, 500, 502 et 504, `Retry-After` n'est pas
   suivi (premier 408 : immédiat une fois, puis la règle générale). Une seule
   table décide, `attenteTransitoire` du lot A, appelée par le planificateur.
   Conséquence : un `Retry-After` passé ou nul ne donne plus une reprise
   immédiate (plancher `initial_ms`, essai du lot A adapté).
2. **Statut HTTP hors de [100, 599]** (R-F-1). Ce n'est pas une réponse
   HTTP : `transport: erreur_transport`, `http_status` nul, code
   `http_hors_bornes` permanent dans l'enregistrement d'acquisition ; le
   planificateur, qui ne voit que `erreur_transport`, rejoue avec un nouveau
   nonce (le schéma n'a pas de place pour ce code). Un `Content-Type` vide
   vaut absent (`null`) : l'enregistrement d'acquisition dit `type_contenu`
   (EX-5.12), le planificateur, pour qui un type absent est admis (schéma),
   classe la même réponse sans jeton `reponse_illisible` ; les deux sont
   permanentes avec alerte.
3. **Entrée refusée par le schéma du planificateur** (R-F-1). Tout résultat
   de client (`reponse_rfc3161`, `reponse_ots`, `inclusion_registre`,
   `echec_registre`) que le schéma refuse devient, par la méthode hors schéma
   `rejeter` (règle 1 d'`INTERFACES.md`, comme `relever` et `revoquer`), une
   issue d'échec conforme : code `entree_non_conforme`, détail = chemin JSON
   de l'écart ; jeton : `echec_permanente` puis la conduite d'une erreur
   permanente ; OpenTimestamps : `echec_transitoire`, soumission rejouée ;
   registre : `echec_registre` de ce code. Plus aucune demande ne reste
   `envoyee` sans issue.
4. **Ligne de file refusée par le schéma** (R-C-1). Elle est consignée
   (`anchor_queue_write_failed`, `reason: demande_non_conforme`, `path`) et
   abandonnée, jamais rejouée ; seule une erreur de disque est rejouée. Une
   ligne de file dont `id ≠ <kind>:<subject.hash>` (EX-8.2) est refusée à la
   lecture comme une ligne tronquée (`id_incoherent`, R-C-4).
5. **`acquisitions.ndjson` illisible par endroits** (R-A-1, EX-8.5 règle 3
   par analogie). Une ligne illisible est ignorée et signalée
   (`illisibles: [{ ligne, raison }]`, `acquisitions_ligne_illisible` une
   fois par fichier et par démarrage), jamais réparée ; le réemploi des
   nonces (AN-6) est contrôlé par un index en mémoire construit à la première
   consultation puis tenu à jour par `ajouterAcquisition` (un autre
   processus qui écrirait le même dépôt appelle `oublierIndexNonces`).
6. **Reçu `0x1` sans le journal attendu** (R-D-1 ; OP-11, EX-4.5, EX-9.9).
   Il ne clôt jamais l'envoi : le reçu est relu sur chaque autre point ; si
   aucun ne rend le journal, l'issue reste incertaine (`recu_incertain`,
   aucun fichier d'issue) et l'envoi, toujours sans issue, est renvoyé puis
   relu (EX-8.16) jusqu'à la capture. Un `deja_fait` sous la clé de chaîne
   sans capture (reçu sans journal, capture manquée après l'issue) relit la
   transaction de l'envoi connu (`envoi-*.json` de même empreinte) et la
   capture (`registry_capture_resumed`) ; `lookup` ne donnant pas le hachage
   de la transaction, un envoi dont le fichier manque reste `deja_fait`.
7. **`stockage_relu` borné** (R-F-3, EX-8.12). Seules les périodes closes
   sans leurs trois demandes finales et le dernier point de chaque période
   ouverte sont transmis ; les séries en mémoire (AN-3) ne gardent que les
   périodes ouvertes, `points` ceux des périodes ouvertes et ceux qu'une
   demande relue désigne. `listerPoints` de l'enregistreur reste une lecture
   de toutes les séries au démarrage (une fois).
8. **Arrêt** (R-F-4, EX-5.8). `arreter()` n'envoie plus rien de nouveau
   (`anchor_send_deferred` : la ligne `envoyee` est écrite, le redémarrage
   reprend par EX-8.12), attend les actions en vol et leurs réponses dans la
   borne du plus long délai de transport configuré plus 5 s
   (`anchoring_stop_timeout` au-delà), puis traite `arret`.
9. **Nonce OpenTimestamps non durable** (lecture a, EX-6.2). Tant que
   `ots/<objet>.nonce` ne s'écrit pas, rien n'est soumis : la soumission est
   rejouée au pas de `retry` (`calendriers_insuffisants`, même engagement en
   mémoire) et l'écriture retentée à chaque reprise.
10. **Prestataire révoqué** (lecture b, EX-8.3). Après `revoquer`,
    l'alternance d'EX-8.9 entre prestataires épuisés exclut le prestataire
    révoqué tant qu'un autre candidat existe ; seul, il reste le dernier
    recours au pas `retry.max_ms`.
11. **`due_at` d'une demande retenue par `min_interval_ms`** (lecture c,
    EX-8.7). Il vaut l'instant d'envoi programmé (dernier envoi + intervalle),
    informatif, en mémoire ; les traces sont inchangées.
12. **Attestation en double dans une preuve ou une réponse de calendrier**
    (lecture d). Le refus (`doublon`, O-1 ; lecture B-4) est gardé : CT-6
    §10.2 ne nomme pas les doublons, la bibliothèque officielle écrase la
    première branche à la fusion (forme non canonique), et une preuve dont
    la lecture dépend de l'ordre d'écrasement n'a pas de forme canonique.
    Tranché depuis par CT-6 révision 0.5 (EX-10.2, EX-10.5 : forme canonique
    d'un nœud, O-1 en échec, raison `doublon`) ; le vecteur
    `ct-6/ots/preuves/o1-attestation-en-double.ots` (`attendu.json` : 13
    preuves, 21 cas ; `python_opentimestamps.parsing` =
    `acceptee_en_ecrasant`) attend `O-1 echoue`, ce que le produit rend, avec
    le détail « doublon : attestation en double sous un même nœud ».
13. **`TimeStampResp` dont le jeton ne se lit pas** (lecture e, EX-5.10
    étape 2, CT-6 §9.3). Le corps est illisible : `reponse_illisible`, non
    `verification_T-1` ; le `.tsr` est écrit tel que reçu (EX-5.14 : réponse
    comprise), aucun `.der` (il n'y a pas de jeton). Les 28 cas de
    `reponses/` sont inchangés.
14. **Structure malformée dans `signedAttrs`** (R-A-2, CT-6 EX-9.7, EX-9.4).
    La lecture de T-1 parcourt chaque valeur d'attribut signé et non signé
    par le lecteur borné (`parcourir` : forme construite ou primitive des
    types universels, `BOOLEAN`, `NULL`), et le lecteur refuse l'étiquette
    universelle 0 ; les 21 jetons mutés de la relecture tombent en T-1 ; les
    39 cas d'`attendu.json` d'alors sont inchangés (41 depuis CT-6 révision
    0.5, lecture 4 de l'alignement ci-dessous). La lecture A-14 ne s'applique
    plus qu'à un `ESSCertID` bien formé dont le contenu ne désigne pas S.
15. **Métriques** (R-F-2, R-F-5, EX-8.15). Les valeurs d'étiquette sont
    normalisées (minuscules, caractères hors de `[a-z0-9_:.-]` remplacés par
    `_`) ; les lignes gardées en mémoire par `Supervision` sont bornées
    (`maxLignes`, 10 000, `dropped`) ; une métrique en défaut est consignée
    une fois et ne fait jamais perdre une ligne du journal.
16. **TLS hors du rôle `interne`** (R-C-5, EX-5.5). AN-1 refuse `http://`
    pour tout rôle autre qu'`interne` dans tout profil (règle 4, message qui
    nomme EX-5.5), comme le transport ; la lecture C-6 est inchangée.
17. **Compteur de série** (R-E-1, AN-26). Le verrou est aussi tenu par
    chemin dans le processus : un second `Compteur` du même processus sur le
    même répertoire est refusé.
18. **`capturer`, `verifierCapture`** (R-D-2, R-D-3). Le certificat jamais
    persisté rend `certificat_indisponible` (CP-4) ; un index ou un bloc
    corrompu rend CP-2 à CP-6 `echoue`, jamais une exception.
19. **`Envoyeur`** (R-D-4). Index en mémoire des envois et de leurs issues
    (chargé une fois, tenu à jour) et des captures (par empreinte, par
    `periodHash`, par transaction ; une absence relit le répertoire une
    fois) ; `envoi(hash)`, `oublierIndex()` pour un autre processus écrivain.

### Lot H3 (alignement sur CT-5 révision 0.4 et CT-6 révision 0.5, contrat final)

1. **`point_manquant` depuis l'instant déclaré** (CT-5 révision 0.4, EX-4.1 :
   « `point_manquant` quand aucun point n'est admis pendant `2 × c_K` après
   le `checkpoint_ts` du dernier point admis » ; 8.9 : « le délai court
   depuis l'instant déclaré du point, non depuis son admission, de sorte
   qu'un point reçu longtemps après sa production, après un saut d'horloge
   ou un arrêt, la lève dès sa relecture, et le point de clôture n'arme
   aucune minuterie » ; traces `point-manquant-saut-horloge` et
   `file-perdue`). La minuterie de cadence est armée à
   `checkpoint_ts + 2 × c_K` du dernier point admis, qu'il vienne d'un
   `point_produit` ou d'un `stockage_relu` ; le démarrage n'arme rien ; un
   point dont `checkpoint_ts ≥ period_end` (point de clôture) et une
   période close n'arment rien. Une minuterie déjà échue à l'admission
   (saut d'horloge) part à l'entrée suivante, avant toute autre minuterie
   échue plus tard, et ses actions sont datées de l'instant où elle était
   due (`t` = `checkpoint_ts + 2 × c_K`), comme la trace l'attend ; la ligne
   `point_manquant` porte toujours `gap_s` = `2 × c_K`. Les deux traces
   révisées passent ; les vingt autres sont inchangées.
2. **Alertes `contresignature_tardive` et `jeton_anterieur_au_point`** (8.9 :
   « `jeton_anterieur_au_point` (`genTime + précision < checkpoint_ts −
   clock_tolerance_s` : majeure) ; `contresignature_tardive` (`genTime +
   précision − checkpoint_ts > c_T` : mineure) » ; trace
   `point-manquant-saut-horloge`, qui attend l'alerte `contresignature_tardive`
   après la ligne `checkpoint_countersigned` du jeton du point de 09:59
   obtenu à 12:30). Le planificateur ne les émettait pas (AN-2 les calculait
   seulement dans `tableEcheances`). Il les émet à la promotion du jeton
   d'un point, après la ligne `checkpoint_countersigned` et les alertes
   d'EX-5.11 (`horloge_suspecte`, `reponse_tardive_promue`), antériorité puis
   retard ; aucune trace ne porte `jeton_anterieur_au_point` ni ne fixe
   l'ordre relatif avec `horloge_suspecte` : cet ordre est une lecture
   (avertissements de la réponse, puis constats sur le point), éprouvée par
   un essai unitaire. Le jeton de la clôture (`period_timestamped`) n'en
   reçoit aucune : la règle parle du point.
3. **`Retry-After` révisé** (EX-8.9, table d'EX-5.12, révision 0.4). Relu mot
   à mot contre le texte révisé : `d = min(retry.max_ms, max(retry.initial_ms,
   Retry-After))` sur 429 et 503 seulement, sans gigue ; `retry_after_s`
   consigné = valeur lue, plafonnée à 604 800 ; `Retry-After` d'une 408, 500,
   502 ou 504 non suivi ; premier 408 immédiat. La correction de la relecture
   adversariale (lecture 1 ci-dessus) est conforme ; rien n'a changé.
4. **CT-6 révision 0.5** (EX-9.7 précisé ; EX-10.2, EX-10.5). Les deux jetons
   `t1-cle-longueur-non-minimale.der` (longueur longue non minimale dans la
   `RSAPublicKey` du `SubjectPublicKeyInfo`) et `t1-extension-mal-formee.der`
   (`keyUsage` encodé en `INTEGER`) tombent en T-1, le reste
   `prerequis_en_echec`, comme `attendu.json` (28 jetons, 41 cas) ; la preuve
   `o1-attestation-en-double.ots` tombe en O-1 avec la raison `doublon` (13
   preuves, 21 cas). Rien n'a changé dans le code : la lecture stricte du
   lecteur DER borné et le refus des doublons (lecture 4 du client
   OpenTimestamps) rendaient déjà l'attendu ; les essais comptent désormais
   ces cas et nomment ces vecteurs.

### Révision 0.6 de CT-5 (D2 : taille de la file ; D3 : décomposition de `d_jeton`)

Texte : CT-5 révision 0.6 (EX-8.5 règles 5 et 7, EX-8.12, EX-4.8, EX-8.2,
EX-8.14, EX-5.15, EX-8.15, EX-3.5) ; schémas `ancrage-v0` (`queue.compact_bytes`)
et `planificateur-ancrage-v0` (`attempts` ≤ 32, `attempts_total`).

| Exigence | Code | Essai |
|---|---|---|
| Copies des schémas | `src/planificateur/schemas-ancrage.mjs`, régénéré à l'identique de `spec/schemas/` | `test/ancrage-planificateur-configuration.test.js` (« les schémas embarqués sont identiques… ») |
| EX-8.5 règle 7 (écriture) : 32 tentatives au plus, `en_cours` toujours, `attempts_total` toujours écrit, `n` jamais renuméroté | `Planificateur.fenetrer`, `nouvelleTentative` (`src/planificateur/planificateur.mjs`) ; `controlerDemande` refuse plus de 32 | `test/ancrage-planificateur-fenetre.test.js` (« relève : la tentative en_cours ancienne… ») ; traces `file-fenetre-32*` |
| EX-8.5 règle 7 (lecture des lignes d'avant 0.6) | `validerLigneDemande`, `totalTentatives` (`src/planificateur/file.mjs`), `chargerDemande` | `test/ancrage-file-compactage.test.js` (« une ligne sans attempts_total… ») ; `test/ancrage-planificateur-fenetre.test.js` (« lecture d'une file d'avant la révision… ») |
| EX-8.12 : rang `attempts_total + 1`, file compactée relue, `.compactage` supprimé | `nouvelleTentative` ; `supprimerResidusCompactage` à `FileDurable.ouvrir` | `test/ancrage-planificateur-fenetre.test.js` (« EX-8.12 : reprise… rang 41 ») ; `test/ancrage-file-compactage.test.js` (« un file-<epoch>.ndjson.compactage resté d'un arrêt… ») ; `test/ancrage-composant-compactage.test.js` (« au démarrage, le .compactage… ») |
| EX-8.5 règle 5 : déclencheurs (clôture ; taille > `compact_bytes` et > `2 × S_0` ; une tentative par minute après échec), procédé (a) à (f), échec non bloquant, borne | `FileDurable.compacter`, `declencher`, `dernieresLignes` ; `ComposantAncrage.remettreCloture` | `test/ancrage-file-compactage.test.js` (procédé, déclencheur, ENOSPC, pas en échec, arrêt à chaque pas, concurrence) ; `test/ancrage-planificateur-fenetre.test.js` (panne de l'étape 5) ; `test/ancrage-composant-compactage.test.js` (clôture, ENOSPC) |
| EX-4.8, AN-1, EX-8.2 : `queue.compact_bytes` facultative, défaut, bornes ; hors projection | `src/composant.mjs` (`demarrer`) ; schéma ; `projection` inchangée | `test/ancrage-composant-compactage.test.js` (« sans la clé… », « 1 048 575 et 1 073 741 825… ») |
| EX-8.14, EX-5.15 : file conservée sous sa dernière forme compactée, seul `.compactage` supprimé | `FileDurable` | `test/ancrage-composant-compactage.test.js` (« à la clôture… aucun fichier n'a disparu hors le .compactage ») |
| EX-8.15 : `attempt` et `attempt_id` sur `anchor_retry`, `anchor_fallback`, `anchor_response_rejected` ; `anchor_queue_compacted`, `anchor_queue_compaction_failed` | `journaliserTentative`, `tentativeDe` ; `EVENEMENTS_JOURNAL` ; ligne `anchor_retry` du composant | traces (24) ; `test/ancrage-planificateur-fenetre.test.js` (panne : chaque tentative sortie se lit au journal) ; `test/ancrage-composant-compactage.test.js` (« prestataire des points coupé… ») |
| EX-3.5, 8.9 : `d_admission_s`, `d_attente_s` depuis l'admission, cinq instants tronqués | `promouvoir` (`admisA` à `pointProduit`, au repli de clôture et, pour une demande relue, `created_at`) | `test/ancrage-planificateur-fenetre.test.js` (« point produit 0,2 s après D_1… », « dans chaque trace… ») ; `test/ancrage-planificateur-traces.test.js` (« les cinq composantes… ») |

Lectures et choix :

1. **Fenêtre en mémoire.** La demande en mémoire est la ligne écrite : la
   fenêtre s'applique à chaque écriture, la file rendue par `file()` est donc
   celle de la file durable. Ce que la règle 7 retire de la ligne reste dans
   la mémoire du processus pour les seules règles qui comptent des
   tentatives : la série d'échecs transitoires consécutifs chez un
   prestataire (attente d'EX-8.9), le nombre d'échecs transitoires
   (OpenTimestamps), l'admission d'une transaction par un nœud (EX-9.5) et
   le nonce de la requête (borne d'une réponse tardive à une tentative
   sortie). Après un redémarrage ces tentatives sont inconnues : les
   attentes restent exactes au-delà de 21 échecs (bornes du schéma : facteur
   ≥ 2 et `initial_ms` ≥ 100, l'attente vaut alors `retry.max_ms`), une ancre
   qui a des tentatives sorties n'est pas tenue pour « encore à envoyer »
   (une transaction a pu partir, CT-4 §8.6), la borne d'une réponse à une
   tentative sortie est nulle.
2. **Demande relue non réécrite.** Une ligne d'avant 0.6 relue garde sa forme
   (sans `attempts_total`) tant qu'elle n'est pas réécrite ; `file()` la rend
   telle quelle, comme la dernière ligne de la file durable.
3. **Instant d'admission d'une demande relue.** Une demande de point est
   créée à l'admission du point ; relue de la file, son instant d'admission
   est son `created_at` ; un point relu du stockage au démarrage
   (`stockage_relu`) est admis à l'instant de sa relecture. Les traces
   régénérées (`redemarrage-reprise` : `d_admission_s` 0) le confirment.
4. **Premier envoi** : gardé en mémoire depuis la tentative de rang 1 ; pour
   une demande relue dont la tentative 1 est sortie, la plus ancienne
   tentative de la ligne.
5. **Pas (e) en échec.** Le renommage étant fait, l'ancien descripteur
   désigne un fichier sans nom : la ligne `anchor_queue_compaction_failed`
   (`step` `repertoire`) est consignée et l'ajout continue sur le fichier
   courant (le neuf, valide), non sur l'ancien descripteur, pour ne perdre
   aucune ligne.
6. **`S_0` à l'ouverture** vaut 0 (aucun compactage précédent dans le
   processus) : une file d'avant 0.6 plus grande que `compact_bytes` est
   compactée dès l'ouverture.
7. **Compactage à la clôture** : appelé par le composant après le
   traitement de `periode_close` (les trois demandes écrites), sous le verrou
   qui sérialise les écritures ; la reconstruction d'une clôture par
   `stockage_relu` n'en déclenche pas.

Essais existants mis à jour : `test/ancrage-planificateur-traces.test.js`
(24 traces au lieu de 22, 7 files de reprise au lieu de 6, cinq composantes
de `d_jeton`) ; `test/ancrage-composant-cli.test.js` (24 traces) ;
`test/ancrage-composant-parcours.test.js` et
`test/enregistreur-ancrage-parcours.test.js` (AN-32 : la file étant compactée
à la clôture, les lignes `envoyee` remplacées ne sont plus dans le fichier ;
l'essai vérifie que chaque nonce d'`acquisitions.ndjson` figure dans les
tentatives de la file, l'ordre ligne `envoyee` puis envoi étant éprouvé par
les 24 traces). Aucun essai existant ne portait de ligne de plus de
32 tentatives ni n'exigeait l'absence d'`attempts_total`.

## Écarts au contrat initial retenus

`INTERFACES.md` est le contrat final et décrit exactement le code livré. Les
écarts au contrat initial retenus à l'assemblage (statuts `echoue`, retours
enrichis de `verifierJeton`, `soumettre` et `mettreANiveau`, `Envoyeur`
construit avec `rpc`, `instance`, `horloge`, `attendre`, `ancrer` par `objet`
et `requestId`, `demarrerServeur` asynchrone, compteur durable du serveur
interne, exports renommés du planificateur, `relever`, `revoquer`,
`reconfigurer`, `ancreEncoreAEnvoyer`, `dernieresAcquisitions`, rubrique F),
les ajouts des corrections de la relecture adversariale (`attenteTransitoire`,
`bornerRetryAfter`, `RETRY_AFTER_MAX_S`, `parcourirDer`, `DepotAncres.ouvrir({ signaler })`,
`lireAcquisitions → { illisibles }`, `oublierIndexNonces`, codes
`http_hors_bornes` et `reponse_illisible` ; `Planificateur.rejeter`,
`ErreurPlanificateur.code|chemin`, `ErreurDemandeNonConforme`, `idCoherent`,
raison `id_incoherent`, `Supervision({ maxLignes })`, `dropped`,
`normaliserValeurEtiquette`, `MAX_LIGNES_DEFAUT`, règle 4 d'AN-1 dans tout
profil ; `Envoyeur.envoi`, `oublierIndex`, `envoisSansIssueParHash`,
`recu_incertain`, `registry_capture_resumed` ; `Compteur.ouverts`,
`Compteur.clefRepertoire` ; `FileTolerante`, `etat()` complété, lignes
`acquisitions_ligne_illisible`, `anchor_send_deferred`,
`anchoring_stop_timeout`, `anchor_queue_write_failed` avec
`reason: demande_non_conforme` et `path`) et ceux de l'alignement sur les
textes révisés (minuterie de `point_manquant` depuis le `checkpoint_ts`
déclaré, alertes `jeton_anterieur_au_point` et `contresignature_tardive` du
planificateur, 22 traces), puis ceux de la révision 0.6 de CT-5 (fenêtre de
32 tentatives, compactage, `d_admission_s`, `attempt`/`attempt_id`,
24 traces) y sont tous reportés, aux rubriques A à F.

## Restes

- Clé de chaîne de classe A à C (étape 7, CT-2 EX-11.19 : le démon refuse de
  démarrer avec une telle classe) ; rotation d'urgence au registre (lecture
  F2-8) ; commande `exporter` d'un outil hors démon (lecture F2-9) ;
  régénération des vecteurs CT-9 (le plan de tests compte les fichiers de
  test : `test/plan-de-tests.test.js` échoue tant qu'ils ne sont pas
  régénérés par l'outillage de la référence, hors salle blanche) ; clé
  `anchoring.registry.instance` dans CT-2 (lecture F2-4).
- Croissance de la file en panne longue : tranchée par la révision 0.6 de
  CT-5 (fenêtre de 32 tentatives et compactage, voir « Révision 0.6 de
  CT-5 » plus haut) ; la taille sous ces règles reste à remesurer par la
  campagne (TM-17).
- Alertes de supervision laissées à CT-8 : `prestataire_injoignable` (aucun
  `obtenue` depuis 15 min) et le volume de requêtes se lisent dans les
  métriques exposées ; le composant ne les lève pas lui-même.

## Dépendances

`@noortrace/noyau` 0.1.0, `@noble/curves` 2.4.0 et `@noble/hashes` 2.4.0
(secp256k1, `src/registre/`), les modules de Node.js 22 (`node:crypto` pour RSA, ECDSA,
X.509 ; `node:http`, `node:https`, `fetch` pour les transports). Rien
d'autre.

## Règle de salle blanche

Le paquet a été écrit sans lire `scripts/lib/**`, `scripts/vecteurs/**`,
`scripts/verify/**`, `scripts/registre/**`, `scripts/e2e/**` ni les tests de
la référence ; les outils publiés (`openssl`, le binaire Go de CT-6,
`npm run e2e:registre`, `python-opentimestamps`) ont été exécutés comme des
boîtes noires. Les juges sont les vecteurs et le texte.
