# @noortrace/enregistreur

Cœur du démon `noortrace`, premier lot de l'étape 4 de la phase 2 : tout ce
qui transforme une capture en événement CT-1 scellé et durable, et la
clôture des périodes, tels que les fixe la spécification normative
[CT-2 version 0.6](../../spec/CT-2-enregistreur.md) (sections 3, 7, 8, 9, 11,
12, 14, 15, 17, annexes A et B), avec [CT-1](../../spec/CT-1-evenements-et-formats.md)
pour les formats et [CT-3](../../spec/CT-3-approbations.md) §12 pour
l'interface du service d'approbation.

Le paquet est écrit à neuf depuis le seul texte de la spécification. Il
importe la bibliothèque noyau [`@noortrace/noyau`](../noyau/LISEZMOI.md) pour
tout ce qu'elle fait (JCS v0, hachage, Ed25519, EIP-191, événement, rotation,
Merkle, manifeste, point de contrôle, dossier, schémas de CT-1) et ne le
réécrit pas. Les vecteurs de `spec/vecteurs/ct-2` et l'annexe A sont le juge.

Les frontaux (MCP, modèle, SDK, OpenTelemetry), le moteur de politique, la
rédaction, le WORM, la haute disponibilité et l'ancrage sont des lots
suivants : [INTERFACES.md](INTERFACES.md) est leur contrat.

## Ce que fait le cœur

- **Construction de l'événement** (§7) : événement partiel sorte par sorte
  (appel d'outil relayé, retenu, refusé, reprise ; échange de modèle ;
  décision d'approbation ; rotation ; politique), `policy.redaction` d'après
  les références (EX-10.20), reprise clé pour clé de la `retenue` pour l'appel
  relayé après approbation et le refus d'un ticket décidé (EX-7.12), effets
  par gabarit évalués sur les valeurs rédigées (EX-7.6), validation contre le
  schéma et E-1 à E-7 avant signature (EX-7.1).
- **Écrivain unique** (§3.4, EX-7.8) : `seq`, `ts` (EX-7.9, recul et saut en
  avant d'EX-7.13, mode dégradé « horloge »), `prev_hash`, annonce de
  politique exigée (EX-9.1), pièces exigées sur disque (EX-8.9), signature
  vérifiée (EX-11.6), validation groupée (EX-12.7), bail vérifié avant chaque
  signature et chaque fdatasync, puis après (EX-13.6, EX-13.10 (2)).
- **Pièces** (§8) : JCS intégral (§8.1, écrit ici : le noyau ne fait que JCS
  v0), pièces texte, non JSON et non rédigeables (EX-8.7), formes fixes du
  cœur, stockage par `sha256` (fichier temporaire, renommage, fsync du
  fichier et du répertoire, jamais de réécriture, EX-8.9, EX-12.6), espace
  libre minimal (14.2, « disque presque plein »).
- **Segments** (§12.1 à §12.4) : en-tête JCS v0, une ligne JCS v0 par
  événement, rotation par taille et à la frontière de période, relecture
  complète du dernier segment au démarrage, troncature d'une fin incomplète,
  corruption jamais tronquée (EX-12.11).
- **Journal d'intention et reprise** (§12.5) : deux lignes et fdatasync avant
  tout relais d'écriture ou soumis à approbation, levée après durabilité,
  levée implicite, événement de reprise, intention sans contexte, corruption
  (EX-12.12 à EX-12.15, EX-12.22), ordre d'EX-9.8.
- **Périodes et clôture** (CT-1 §9, §10 ; 3.1) : manifeste, signature par la
  clé en vigueur, périodes vides comprises (continuité), nonce frais.
- **Points de contrôle** (§12.10) : instants alignés à 1 s près, point de
  clôture, série en ajout seul, chaînage, reprise de la série, remise au
  composant d'ancrage.
- **Signataires** (§11) : interface commune (EX-11.18) ; enveloppe qui borne
  le message (EX-11.7), applique le délai et une seule seconde tentative,
  vérifie chaque signature (EX-11.6) ; classe D (fichier PKCS#8, chiffré ou
  non), refusée en production (EX-11.8) ; rotation (EX-11.15).
- **Journal sur lui-même** (§9) : événement de politique en tête du journal
  et à chaque changement (EX-9.1, EX-9.2, EX-15.4 pas 6), décision, rotation,
  expiration par le noyau seul (EX-9.4) ; journal d'exploitation NDJSON
  (EX-9.5 à EX-9.7, EX-17.2 à EX-17.4).
- **Interface du service d'approbation, côté démon** (§7.5) : `evaluer` et
  sa validation (EX-7.16), `charger`, `ouvrir`, `decisions` et `acquitter`
  (EX-7.19), `consommer` (EX-7.20), `expiration` ; SG-1 à SG-7 (EX-7.5) ;
  RL-1 à RL-4 (EX-7.21) ; MAC de relais (EX-7.22) ; fichiers des
  approbations (EX-12.23) ; canal HTTP (EX-7.14) ; service factice pour les
  tests (`@noortrace/enregistreur/factice`).
- **Mode dégradé** (§14, pour le cœur) : raisons `stockage`, `cle`, `bail`,
  `horloge`, `attente`, `approbation` ; événements en attente et leur
  scellement (EX-14.8 à EX-14.10, EX-4.46) ; sortie des modes « clé » et
  « stockage » (EX-14.11).
- **Configuration** (§15) : JSON strict, schéma (toutes les erreurs), règles
  hors schéma de la part du cœur, secrets (`env`, `file`), rapport et code 2,
  rechargement de la politique (EX-15.5), commande `validate-config`.
- **Supervision** (§17) : `/healthz`, `/readyz`, `/metrics` ; métriques de
  l'écrivain, de la clé, du bail, du mode dégradé.
- **Export d'un dossier minimal** (CT-1 §11) : douze parties v0 (réservées
  absentes, « hors périmètre CT-1 ») et la treizième, `points-de-controle.json`.

## Démarrer le démon

```sh
noortrace validate-config configuration.json    # pas 1 à 3 d'EX-15.4 ; code 0 ou 2
noortrace --config configuration.json           # démarre ; SIGTERM, SIGINT : arrêt propre ; SIGHUP : rechargement
```

Une configuration invalide n'est jamais servie : une ligne par erreur sur
stderr (`config_invalid : <pointeur JSON> : <règle> ; valeur : <valeur>`, sans
la valeur pour un secret) et code de retour 2. Au démarrage, dans l'ordre
d'EX-15.4 et d'EX-9.8 : stockage, bail, clé publique et signature de test,
relecture et troncature, reprise des intentions, événements en attente,
événement de politique (refus de démarrer si l'ensemble a changé sans changer
`policy.version`, EX-10.21), fichiers des approbations, `charger`, `ouvrir`,
`consommer`, ligne `startup`, supervision, minuteurs (points, clôtures,
remises).

## Configuration

Le document unique de §15, validé contre `configuration-enregistreur-v0`
(copie dans `schemas/`, avec `politique-redaction-v0`,
`politique-approbation-v0`, `ticket-v0` et `evenement-v0` ; un test les
compare à `spec/schemas`). Le cœur lit : `recorder`, `signer` (classe D :
`backend.type: "file"`, `path`, `passphrase`), `storage` (`root`,
`segment_max_bytes`, `min_free_bytes`, `fsync`, `relay_mac_key`, `seal.worm.prefix`),
`lease` (`file`), `clock`, `checkpoint_interval_s` (défaut 60),
`supervision`, `limits.pending_max_bytes`, `tools.default_timeout_ms`,
`mcp.hosts` et `sdk.hosts` (reprise d'une intention sans contexte),
`policy` (ensemble de politique, version, gabarits d'effets, classes,
`approval` pour SG-4, SG-7, RL-4, EX-9.4, `failure.pending_max_events`).

Règles hors schéma vérifiées par ce lot (EX-15.4 pas 3) : classe et backend
du signataire, classe D en production, `verify_after_sign`, alias
`noortrace`, `tools.prefix`, cadence des points, `lease.renew_ms <
lease.ttl_ms / 2`, `fencing` en production, rétention et WORM (EX-12.19,
EX-12.30, EX-12.31), clé de chaîne de classe D en production, gabarits
d'effets, chemins des routes, jetons statiques, `otel`, mode `retenir`, mode
observation (EX-15.8), approbateurs de test.

## Fichiers sur disque

Sous `storage.root/<org_id>/<journal_id>/` (hexadécimal sans `0x`, EX-12.1) :

| Fichier | Écrit par | Forme |
|---|---|---|
| `journal.json` | création du journal, une fois | `{ version, org_id, journal_id, created_at, recorder }` |
| `segments/seg-<first_seq:16>-<epoch:20>.ndjson` | écrivain | en-tête JCS v0, puis une ligne JCS v0 par événement (12.2) |
| `pieces/<xx>/<sha256>` | `ecrirePiece` | octets de la pièce |
| `intentions/intentions-<epoch:20>.ndjson` | écrivain | lignes JCS intégral : intention, contexte, levée (12.5) |
| `attente/attente-<epoch:20>.ndjson` | mode dégradé, au mieux | `{ pending_id, captured_at, event, pieces, intent_id }` (14.5) |
| `approbations/approbations-<epoch:20>.ndjson`, `mac-<epoch:20>.ndjson` | noyau | lignes de EX-12.23 ; ligne de contrôle du MAC en tête |
| `manifestes/periode-<period_start:10>.json`, `.sig` | clôture | `JSON.stringify(objet, null, 2)` + `\n` |
| `points/periode-<period_start:10>.ndjson` | points de contrôle | une ligne JCS intégral par point signé |

Hors du répertoire du journal : le verrou du bail (`lease.store.path`) et
son époque (`<path>.epoch`), le journal d'exploitation
(`supervision.ops_log.path`, rotation par taille). Il n'y a aucun fichier
d'état mutable : l'état de l'écrivain et les index (tickets, décisions,
politiques, clés) se dérivent des segments à la reprise.

## Modules

| Module | Domaine | Sections |
|---|---|---|
| `configuration.mjs`, `schema.mjs`, `secrets.mjs` | chargement, validation, secrets | §15, EX-15.1 à EX-15.8 |
| `capture.mjs`, `effets.mjs` | capture → événement | §7.1 à §7.4, EX-7.6, EX-7.12 |
| `jcs-integral.mjs`, `pieces.mjs` | pièces | §8 |
| `ecrivain.mjs`, `segments.mjs`, `fichiers.mjs` | écrivain unique, segments, durabilité | §3.4, §12.1 à §12.4 |
| `intentions.mjs` | journal d'intention | §12.5 |
| `reprise.mjs`, `index-chaine.mjs` | relecture, reprise | EX-12.10, EX-12.14, EX-9.8 |
| `periodes.mjs` | périodes et clôture | CT-1 §9, §10 ; 3.1 |
| `points.mjs` | points de contrôle | §12.10 |
| `signataires.mjs` | signataires (interface, classe D) | §11 |
| `bail.mjs` | bail (interface, magasin `file`) | §13 (part du cœur) |
| `lui-meme.mjs` | journal sur lui-même | §9.1 |
| `journal-exploitation.mjs` | journal d'exploitation | §9.2, §17.3 |
| `supervision.mjs`, `degrade.mjs`, `horloge.mjs` | supervision, mode dégradé, horloge | §17, §14, §7.4 |
| `approbations.mjs`, `service-approbation-http.mjs`, `service-approbation-factice.mjs` | interface du service d'approbation | §7.5, §12.9, CT-3 §12 |
| `ancrage.mjs`, `worm.mjs` | remise à l'ancrage, copies WORM (interfaces) | §12.10, §12.6 |
| `dossier.mjs` | export d'un dossier minimal | CT-1 §11 |
| `coeur.mjs`, `cli.mjs`, `bin/noortrace` | assemblage, démarrage, démon | §3, §15.4, §15.6 |

## Ce qui relève des lots suivants

Frontal MCP (§4) ; frontal modèle et passerelle (§5) ; SDK, adaptateurs et
ingestion OpenTelemetry (§6) ; moteur de politique (classification, matrice
de 14.2 par classe, mode d'attente `retenir`, mode observation, candidats) et
vrai service d'approbation (CT-3) ; rédaction (§10 : détecteurs, motifs,
budget, coffre) et ses contrôles de configuration (EX-10.6, EX-10.23) ;
validation de `policy.approval.rules` (CT-3 EX-4.2, EX-8.2) ; collisions de
noms annoncés (EX-4.11) ; signataires des classes A, B et C ; magasins de
bail `postgresql` et `etcd`, attente du bail, bascule (§13) ; copies WORM,
registre des copies, contrôle du verrou, relevé, gel juridique (§12.6,
§12.11) ; purge des pièces (EX-12.20) ; attribut append-only (EX-12.18) ;
ancrage (CT-5) et registre (CT-4) ; exportateur complet de CT-6 ; contrôles
périodiques de la supervision (EX-17.5) ; démonstration (§19).

## Lectures de passages ambigus

Chaque lecture est tranchée par le texte et, quand un vecteur la porte, par
le vecteur ; l'implémentation de référence n'a pas été consultée.

1. **Délégation d'une décision d'approbation.** CT-2 7.2, table
   `delegation`, colonne « Événements du journal sur lui-même » :
   `"noortrace-enregistreur"`, `scope "journal:administration"` ; mais la
   table `code` met la décision à part (« décision : ceux de l'appel
   retenu »), et le vecteur `evenements/journal-demo` (seq 6) comme CT-1
   annexe A (seq 3) portent la délégation de l'appel retenu. Lecture : la
   décision reprend la délégation et `code.model`, `code.prompt_version` de
   la `retenue` ; politique et rotation portent la délégation du journal.
2. **Ligne invalide d'un segment : troncature ou corruption** (EX-12.10 pas 2
   et 3 contre EX-12.11). EX-12.10 dit que « la première ligne invalide ou
   incomplète » marque la fin du contenu durable ; EX-12.11 réserve la
   troncature à « une fin de fichier incomplète (ligne sans \n ou JSON
   inachevé) ou [aux] octets nuls de remplissage ». Lecture : seule une
   dernière ligne sans `\n`, ou faite d'octets nuls (jusqu'à la fin), est
   tronquée ; toute autre ligne invalide (hash, signature, chaînage, schéma,
   ligne illisible suivie d'autres) est une corruption : `segment_corrupted`,
   mode dégradé « stockage », aucune écriture jusqu'à intervention.
3. **`ts` après une clôture.** EX-7.9 : `ts = max(ts lu, ts précédent)` ;
   EX-7.11 : « la clôture d'une période n'a lieu qu'après le dernier
   événement dont le `ts` lui appartient ». Un recul de l'horloge sous le
   seuil, après une clôture sans événement nouveau, donnerait un `ts` dans
   une période close. Lecture : l'écrivain prend aussi pour plancher
   `period_end` de la dernière période close.
4. **Première période et périodes vides.** CT-1 §10.1 : `first_seq = 1` pour
   la première période ; §10.3 : continuité. Lecture : la première période
   est celle du `ts` de seq 1 (l'événement de politique, écrit au
   démarrage) ; chaque heure suivante a son manifeste, vide ou non, y compris
   les heures d'un arrêt, closes à la reprise avec un point de clôture
   (`tree_size` = 0 pour une période vide).
5. **Rotation de segment à la clôture** (EX-12.4 (a), EX-13.9). Un segment
   qui n'a reçu aucun événement n'est pas tourné à la clôture (sinon un
   segment réduit à son en-tête par heure) ; chaque démarrage ouvre un
   segment neuf (nouvelle époque), comme EX-13.9 le dit.
6. **Magasin de bail `file`** (13.2 : `flock(LOCK_EX | LOCK_NB)`). Node.js
   n'offre pas `flock(2)` sans module natif : le verrou est un fichier créé en
   exclusion qui porte le PID du détenteur, repris quand ce processus n'est
   plus vivant (arrêt brutal) ; l'époque est `<path>.epoch`, incrémentée et
   forcée sur disque à chaque acquisition. Un bail perdu exige un redémarrage
   (EX-13.6 interdit la reprise « à chaud » sans relecture).
7. **Clé suivante de classe D.** 15.1 nomme `signer.rotation.next_key_id` sans
   dire où est son fichier. Lecture : même répertoire que
   `signer.backend.path`, nom `<next_key_id>` suivi de l'extension du fichier
   courant ; même phrase de passe.
8. **Signature de test** (EX-15.4 pas 5, EX-14.11) et EX-11.18 (« aucun autre
   message n'est jamais soumis au signataire »). Lecture : le message de test
   est `P_S` seul, de la forme `P_S ‖ C` avec `C` vide, qu'aucun événement ne
   peut produire (sa forme canonique n'est jamais vide).
9. **Signature d'une clé dont la clé publique est inconnue à la relecture.**
   EX-12.10 pas 2 exige une `sig` qui vérifie « sous la clé en vigueur ». La
   clé initiale n'est pas dans la chaîne ; si le signataire ne la détient
   plus, sa clé publique manque. Lecture : la signature n'est alors pas
   vérifiée à la relecture (hash, `seq`, `prev_hash` le sont) ; une clé
   connue qui ne vérifie pas est une corruption.
10. **SG-4 et `approval.at`** (EX-7.5, EX-7.11). SG-4 porte sur « l'instant
    d'écriture de la décision, qui sera `approval.at` », connu seulement quand
    l'écrivain fixe `ts`. Lecture : SG-4 est vérifiée avant le scellement à
    l'instant courant, puis de nouveau au `ts` fixé ; un `ts` au-delà de
    l'échéance annule le scellement (`acquitter` `refuse`,
    `echeance_depassee`).
11. **Pointeur ou littéral dans un gabarit d'effets** (EX-7.6 : « pointeur JSON
    RFC 6901 dans les arguments ou le résultat (`/arguments/...`,
    `/result/...`), ou chaîne fixe »). Lecture : une chaîne est un pointeur si
    et seulement si elle commence par `/arguments` ou `/result` (suivi de `/`
    ou en fin) ; une autre chaîne commençant par `/` est refusée à la
    validation.
12. **Fichiers de période.** 12.1 nomme `manifestes/periode-<period_start>.json`
    et `.sig` sans fixer leurs octets. Lecture : `JSON.stringify(objet, null,
    2)` suivi d'un saut de ligne, la mise en forme des parties de dossier de
    CT-1 §11.1, de sorte que l'exportateur les copie octet pour octet.
13. **`checkpoint_ts` d'un point.** CT-1 §10.5 : instant de production. Le
    point de clôture est produit après `period_end` : son `checkpoint_ts` vaut
    `generated_at` du manifeste (≥ `period_end`). Un `checkpoint_ts` n'est
    jamais antérieur au point précédent ni à `period_start`.
14. **Annonce d'une version déjà annoncée** (EX-10.21 : « Le changement DOIT
    s'accompagner d'une nouvelle valeur de `policy.version` »). Lecture : un
    ensemble dont la version a déjà été annoncée avec une autre empreinte est
    refusé ; un retour à un ensemble déjà annoncé, même version et même
    empreinte, est annoncé de nouveau.
15. **Fichier d'attente après scellement.** 14.5 ne dit pas quand le fichier
    `attente-<epoch>` est retiré. Lecture : au démarrage, les fichiers des
    époques antérieures sont scellés puis supprimés ; un arrêt pendant ce
    scellement peut sceller une seconde fois un événement en attente (perte
    admise, consignée par `pending_flushed`).
16. **`cles.json` exporté.** CT-1 §11.2 laisse `source` libre et la validité de
    la clé initiale « telle qu'annoncée ». Lecture : la clé initiale est
    valide depuis `created_at` de `journal.json`, chaque rotation ferme la
    précédente et ouvre la suivante à son `ts` (CT-1 §8 règle 3) ; `source`
    nomme `journal.json` et les rotations.
17. **Événements partiels et EX-9.1.** Un événement en attente, de reprise ou
    d'un appel commencé avant un rechargement porte la `policy_version` de sa
    capture ; l'écrivain refuse toute version jamais annoncée dans le journal.
18. **Délai de `consommer`.** CT-3 §12.7 dit « nouvel essai, idempotent » sans
    borne : le cœur réessaie cinq fois (200 ms, 400 ms…) puis au prochain
    démarrage (EX-7.20).

## Tests

Depuis la racine du dépôt, après `npm ci` :

```sh
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-annexe-a.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-journal.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-reprise.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-config.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-approbations.test.js
```

- `enregistreur-coeur-vecteurs` : `jcs-integral`, `evenements/journal-demo`
  reconstruit octet pour octet par l'écrivain (événements, segment, journal
  d'intention, manifeste de clôture), part de §8 de `pieces-mcp`,
  `pieces-modele` et `redaction/cas.json`, inventaire des fichiers rejoués et
  de ceux des lots suivants ;
- `enregistreur-coeur-annexe-a` : l'annexe A de CT-2, octet par octet ;
- `enregistreur-coeur-journal` : un journal produit par le cœur (échanges,
  appels, refus, approbation, rotation, points, clôture) vérifié par le noyau,
  et le dossier minimal de l'appel approuvé vérifié par le noyau et par le
  binaire Go (construit par `verificateur/scripts/construire.sh` avec
  go1.27.3 ; sans lui, ce test est en attente) ;
- `enregistreur-coeur-reprise` : processus tué pendant l'écriture, segment
  déchiré, octets nuls, intention ouverte, corruption, levée implicite,
  panne du signataire après relais ;
- `enregistreur-coeur-config` : `validate-config`, refus de démarrer, classe D
  en production, horloge qui recule ou saute, rechargement ;
- `enregistreur-coeur-approbations` : EX-7.16, SG-, mode dégradé, expiration
  par le noyau seul, canal HTTP.

Les répertoires de test sont créés sous `os.tmpdir()`.

## Règle de salle blanche

Ce paquet et ses tests sont écrits d'après le seul texte de CT-2 (et des
passages de CT-1, CT-3, CT-7 qu'il cite), des schémas et des données des
vecteurs de `spec/vecteurs/ct-2`. Ni leur code ni leurs tests n'ouvrent, ne
cherchent ni n'importent `scripts/lib/**`, `scripts/vecteurs/**`,
`scripts/verify/**`, `test/enregistreur*.test.js` (hors
`test/enregistreur-coeur*`), `test/approbation.test.js`,
`test/journal.test.js`, les vérificateurs indépendants
(`spec/vecteurs/*/verificateur-independant/`) ni les répertoires
`confrontation/`.

## Dépendances

| Dépendance | Version | Usage |
|---|---|---|
| `@noortrace/noyau` | 0.1.0 (espace de travail) | formats et cryptographie de CT-1 |
| `node:crypto`, `node:fs`, `node:http` | Node.js ≥ 22 | PKCS#8, HMAC-SHA-256, fichiers, supervision, canal du service |

Aucune autre dépendance d'exécution.
