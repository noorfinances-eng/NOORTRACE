# @noortrace/noyau

Bibliothèque noyau de NOORTRACE, étape 1 de la phase 2 : forme canonique,
hachage, signatures, chaînage, arbre de Merkle, manifeste, point de contrôle
et dossier de preuve, tels que les fixe la spécification normative
[CT-1 version 0.4](../../spec/CT-1-evenements-et-formats.md) (avec la section 7
de [CT-7](../../spec/CT-7-securite-et-conformite.md), qui fait foi pour
l'attestation de périmètre).

Le paquet est écrit à neuf depuis le seul texte de la spécification ; il ne
reprend rien de l'implémentation de référence qui a produit les vecteurs
(`scripts/lib/journal.mjs`). Les vecteurs de `spec/vecteurs/ct-1` sont le juge
entre les deux : la bibliothèque les rejoue tous (`test/noyau-vecteurs.test.js`).

## Ce que fait le paquet

- lit le JSON strictement (clé en double, substitut isolé, nombre non entier ou
  hors de l'intervalle sûr : refus) et calcule la forme canonique JCS v0, sans
  borne de profondeur par défaut (CT-1 §4 n'en fixe pas) et sans récursion :
  une imbrication arbitraire n'épuise jamais la pile ; l'option
  `profondeurMax` applique une borne explicite (`PROFONDEUR_CT6`, 128, celle
  de CT-6 EX-4.13) ;
- décode les horodatages RFC 3339 à la milliseconde sans jamais renormaliser
  une date inexistante ; n'admet que les entiers sûrs et l'hexadécimal minuscule
  préfixé ;
- hache et signe événements, manifestes et points de contrôle (SHA-256 et
  Ed25519 « pur » avec les préfixes de domaine de l'annexe B), vérifie Ed25519
  sans cofacteur en refusant S non réduit, les encodages non canoniques et les
  clés de petit ordre ; signe et recouvre les signatures EIP-191 des
  approbateurs (règle « s bas », v ∈ {27, 28}) ;
- vérifie un journal (E-1 à E-11 pour chaque événement, puis C-1, C-2, C-3 dans
  l'ordre du fichier) en rapportant tous les symptômes de la table 7.2 ;
- construit l'arbre de Merkle RFC 6962 (racine nulle de la période vide), les
  preuves d'inclusion et de cohérence, et les vérifie par les algorithmes de la
  RFC 9162 reproduits dans CT-1 ;
- hache, signe et enchaîne les manifestes (continuité, PeriodMeta, empreinte
  d'ancre), hache et signe les points de contrôle, vérifie une série de points
  contre son manifeste avec les noms de règles de §10.5 ;
- vérifie un dossier de preuve v0 à douze, treize ou quatorze parties : tous
  les contrôles de §11.4 (D-, E-, C-, M-, P-, A-, K-), le verdict, la liste
  exacte des contrôles en échec, et les vérifications AT-1 à AT-7 de
  l'attestation de périmètre, signalées sans effet sur le verdict ;
- valide contre les cinq schémas de `spec/schemas` que CT-1 nomme, avec un
  validateur JSON Schema écrit dans le paquet, limité aux mots-clés que ces
  schémas emploient et qui refuse tout autre mot-clé.

La bibliothèque est pure : aucun module de `src/` ne lit de fichier, sauf
`src/dossier-fichiers.mjs`, exporté à part ; aucune horloge n'est lue (un
instant, quand il sert, est un paramètre, comme `generated_at`). Les schémas
sont embarqués dans `src/schemas-v0.mjs`, copie à l'identique de
`spec/schemas`, que `test/noyau.test.js` compare membre pour membre aux
originaux.

Lecture d'un répertoire : `src/dossier-fichiers.mjs` n'ouvre un fichier
qu'après `lstat`, s'il est ordinaire (puis sans suivre de lien), et ne le lit
que s'il ne dépasse pas sa limite (`TAILLES_MAX`, valeurs de CT-6 EX-4.13) :

| Fichier | Limite |
|---|---|
| `dossier.json` | 1 Mio |
| `evenement.json`, `voisins.json`, `chemin.json`, `manifeste.json`, `manifeste.sig`, `cles.json`, `approbations.json` | 16 Mio chacun |
| `jeton-rfc3161.der` | 64 Kio (CT-6 EX-9.3) |
| `preuve.ots` | 256 Kio (CT-6 EX-10.2) |
| `registre.json`, `certificat-commit.json` | 64 Mio |
| `validateurs.json` | 1 Mio |
| `points-de-controle.json` | 1 Mio (CT-6 EX-4.14) |
| `attestation-perimetre.json` | 4 Mio (CT-6 EX-4.15) ; au-delà, SHA-256 seul, en flux, jusqu'au plafond de 64 Mio (`PLAFOND_LECTURE`) |

Un fichier plus grand n'est pas lu : il est rendu comme `FichierNonLu`
(`{ taille, sha256 }`), et `verifierDossier` en fait un échec, jamais une
exception : du contrôle qui porte la partie si elle est déclarée présente
(CT-6 EX-4.11), de D-2 si elle est déclarée absente. `verifierDossier`
applique les mêmes limites aux octets qu'on lui passe directement.

Ce que le paquet ne fait pas : les vérifications des parties réservées à CT-4
et CT-5 (jeton RFC 3161, preuve OpenTimestamps, registre : contrôles 4, 5 et 8,
fixés par CT-6). Une partie réservée déclarée présente est rapportée comme non
vérifiée (`non_executes_bloquants`) et rend le verdict invalide ; une ancre de
point de contrôle non nulle (K-7, K-8, K-9) n'est vérifiée que par une fonction
fournie dans `options.verificateursAncres` (K-8 recalcule seulement
l'empreinte et le `doc_type`).

## Utilisation

```js
import { verifierDossier, verifierJournal, jcs, analyserJson } from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";

const rapport = verifierRepertoireDossier("chemin/du/dossier");
rapport.verdict;             // "valide" ou "invalide" (null si dossier.json est illisible)
rapport.controles_en_echec;  // liste exacte, dans l'ordre de CT-1 §11.4
rapport.perimetre;           // AT-1 à AT-7, attestation retenue, avertissements AV-AT-
```

## Correspondance des sections de CT-1 et des modules

| Section de CT-1 | Module de `src/` |
|---|---|
| §3 conventions d'encodage (hexadécimal, horodatages, entiers, base64) | `conventions.mjs` |
| §4 forme canonique JCS v0, lecture JSON stricte | `json-strict.mjs` |
| §5 événement v0, §5.4 références et rédaction | `evenement.mjs` |
| §6.1, §6.2 hachage et signature Ed25519 ; §6.3 EIP-191 ; annexe B préfixes et points de petit ordre | `hachage.mjs`, `evenement.mjs` |
| §7 chaînage, table 7.2, C-1 à C-3 sur un journal | `chainage.mjs` |
| E-1 à E-11 (§11.4) pour un événement | `controles-evenement.mjs` |
| §8 rotation de clé, E-10 | `rotation.mjs` |
| §9 arbre de Merkle, période vide, inclusion ; §10.7 cohérence | `merkle.mjs` |
| §10.1 à §10.4 manifeste, continuité, PeriodMeta, empreinte d'ancre | `manifeste.mjs` |
| §10.5, §10.6, §10.8 point de contrôle et série | `point-de-controle.mjs` |
| §11.2 `cles.json` (première partie de E-8) | `cles.mjs` |
| §11.1, §11.2, §11.4 dossier, contrôles D-, E-, C-, M-, P-, A-, K-, verdict | `dossier.mjs` |
| §11.2 et §11.4 attestation de périmètre, AT-1 à AT-7 (CT-7 §7) | `attestation.mjs` |
| schémas nommés par CT-1 (`spec/schemas`) | `schemas-v0.mjs`, `schemas.mjs`, `validation-schema.mjs` |
| lecture d'un répertoire de dossier | `dossier-fichiers.mjs` |

## API publique

Point d'entrée `@noortrace/noyau` (`src/index.mjs`) :

### Conventions (`conventions.mjs`)

- `ENTIER_MAX` — plus grand entier sûr, 2^53 − 1.
- `ZERO32` — trente-deux octets nuls en hexadécimal préfixé.
- `estHex(valeur, octets?)` — hexadécimal minuscule préfixé 0x, de longueur donnée.
- `hexVersOctets(texte, octets?)` — décode l'hexadécimal minuscule préfixé, refuse le reste.
- `octetsVersHex(octets)` — encode en hexadécimal minuscule préfixé.
- `concatener(...parties)` — concatène des suites d'octets.
- `octetsEgaux(a, b)` — égalité de deux suites d'octets.
- `estEntierSur(valeur)` — entier de l'intervalle sûr.
- `decoderHorodatage(texte)` — horodatage de §3 en millisecondes, null si la date n'existe pas.
- `estHorodatage(texte)` — l'horodatage se décode.
- `ecrireHorodatage(ms)` — écrit un instant au format de §3.
- `decoderBase64Canonique(texte, maxOctets?)` — base64 canonique (remplissage exact, bits de bourrage nuls), sinon null.
- `encoderBase64(octets)` — base64 standard avec remplissage.
- `utf8(texte)` — encode en UTF-8.

### JSON strict et JCS v0 (`json-strict.mjs`)

- `CODES_FORME_CANONIQUE` — codes d'erreur relevant de E-2.
- `PROFONDEUR_CT6` — 128, profondeur d'imbrication de CT-6 EX-4.13, à passer en option `profondeurMax` (CT-1 n'en fixe aucune).
- `ErreurJson` — erreur de lecture ou de forme canonique (`code`, `formeCanonique`).
- `decoderUtf8(octets)` — décode de l'UTF-8 bien formé sans marque d'ordre d'octets ; un substitut encodé (CESU-8) est un `substitut_isole` (E-2).
- `analyserJson(source, options?)` — lecture stricte et itérative (refus de E-2 ; options pour le document de politique ; `profondeurMax`, aucune par défaut).
- `chaineBienFormee(s)` — aucune moitié de substitut isolée.
- `jcs(valeur, options?)` — forme canonique JCS v0, itérative, structure cyclique refusée (`profondeurMax`, aucune par défaut).
- `jcsOctets(valeur, options?)` — forme canonique en UTF-8.
- `canoniserTexte(source, options?)` — forme canonique d'un texte JSON, ou null s'il est refusé.
- `egaliteJson(a, b)` — égalité de deux valeurs JSON, membre pour membre, itérative.

### Hachage et signatures (`hachage.mjs`)

- `PREFIXES` — les neuf préfixes de domaine (P_H, P_S, P_M, P_SM, P_A, P_R, P_K, P_SK, P_P).
- `sha256(octets)` — SHA-256.
- `keccak256(octets)` — Keccak-256 d'Ethereum.
- `sha256Hex(octets)` — SHA-256 en hexadécimal préfixé.
- `POINTS_PETIT_ORDRE` — les huit encodages de petit ordre de l'annexe B.
- `encodageEd25519Canonique(octets)` — encodage de point avec y < p.
- `clePubliqueEd25519Admise(cle)` — clé canonique et hors des points de petit ordre.
- `clePubliqueEd25519(graine)` — clé publique d'une graine de 32 octets.
- `signerEd25519(graine, message)` — signature Ed25519 pure.
- `verifierEd25519(cle, message, signature)` — vérification sans cofacteur, avec les refus de §6.2.
- `messageEip191(condense)` — message `personal_sign` d'un condensé de 32 octets.
- `adresseDepuisClePrivee(cle)` — adresse Ethereum d'une clé secp256k1.
- `signerEip191(cle, condense)` — signature EIP-191 canonique, r ‖ s ‖ v.
- `recouvrerAdresseEip191(condense, signature)` — adresse recouvrée, avec les refus de §6.3.
- `verifierEip191(condense, signature, adresse)` — signature canonique de cette adresse.
- `formeHauteEip191(signature)` — forme « s haut » d'une signature (pour les tests de refus).

### Schémas (`validation-schema.mjs`, `schemas-v0.mjs`, `schemas.mjs`)

- `MOTS_CLES` — mots-clés JSON Schema reconnus ; tout autre est refusé.
- `ErreurSchema` — défaut d'un schéma (mot-clé inconnu, référence introuvable…).
- `RegistreSchemas` — registre de schémas draft 2020-12 et validation.
- `SCHEMA_EVENEMENT` — copie de `evenement-v0.schema.json`.
- `SCHEMA_MANIFESTE` — copie de `manifeste-v0.schema.json`.
- `SCHEMA_POINT_DE_CONTROLE` — copie de `point-de-controle-v0.schema.json`.
- `SCHEMA_ATTESTATION_PERIMETRE` — copie de `attestation-perimetre-v0.schema.json`.
- `SCHEMA_DOSSIER` — copie de `dossier-v0.schema.json`.
- `REGISTRE` — registre des cinq schémas et des deux enveloppes dérivées.
- `SCHEMAS` — noms de schémas admis et leur référence.
- `validerSchema(nom, instance)` — valide contre un schéma nommé.

### Événement (`evenement.mjs`)

- `NOMS_RESERVES` — les quatre noms réservés de `noortrace.`.
- `CLES_EVENEMENT` — les dix-sept clés d'un événement.
- `sorteEvenement(e)` — appel d'outil, échange, décision, rotation, politique.
- `estNomReserve(outil)` — l'un des quatre noms réservés.
- `corpsEvenement(e)` — E', l'événement sans `hash` ni `sig`.
- `formeCanoniqueEvenement(e)` — C = JCS(E').
- `hacherEvenement(e)` — SHA-256(P_H ‖ C).
- `messageSignatureEvenement(e)` — P_S ‖ C.
- `scellerEvenement(e, graine)` — calcule `hash` et `sig`.
- `verifierSignatureEvenement(e, cle)` — vérifie `sig`.
- `objetApprobation(e)` — objet signé A d'une approbation.
- `condenseApprobation(A)` — D_A = SHA-256(P_A ‖ JCS(A)).
- `signerApprobation(cle, A)` — signature EIP-191 d'un approbateur.
- `creerReference(octets, options?)` — référence à une pièce stockée.
- `creerReferenceEnLigne(value, options?)` — référence en ligne (pièce = JCS(value)).
- `verifierReferenceEnLigne(ref)` — sha256 et length d'une référence en ligne (E-6).
- `verifierPiece(ref, octets)` — une pièce fournie à part est celle de la référence (E-6).
- `referencesEvenement(e)` — les références d'un événement et leur emplacement.

### Clés (`cles.mjs`)

- `indexerCles(cles, attendus?)` — lit `cles.json` (première partie de E-8) et l'indexe.
- `dansValidite(cle, instant)` — instant dans la validité annoncée, bornes incluses.

### Rotation (`rotation.mjs`)

- `corpsRotation(annonce)` — R, l'annonce sans `counter_sig`.
- `messageRotation(annonce)` — P_R ‖ JCS(R).
- `annoncerRotation(champs, graineNouvelle)` — annonce contresignée par la nouvelle clé.
- `champsEvenementRotation(annonce)` — `execution` et `effects` d'un événement de rotation.
- `verifierContresignature(annonce)` — `counter_sig` sous `new_public_key`.
- `annonceRotation(e)` — l'annonce d'un événement de rotation si elle a la forme de §8.
- `ecartsRotation(e, indexCles)` — écarts au contrôle E-10.

### Contrôles d'un événement (`controles-evenement.mjs`)

- `CONTROLES_EVENEMENT` — E-1 à E-11.
- `STATUTS` — reussi, echoue, non_execute.
- `ecartsSorte(e)` — écarts à la cohérence de la sorte (E-3).
- `controlerEvenement(e, contexte?)` — E-1 à E-11 et le hash recalculé.
- `hashRecalcule(e)` — hash recalculé, ou null.
- `nouvelleCle(e)` — `new_key_id` d'une rotation, sinon null.

### Chaînage (`chainage.mjs`)

- `ORDRE_CONTROLES` — ordre de rapport des contrôles de §11.4.
- `trierControles(ids)` — trie des identifiants dans cet ordre.
- `verifierJournal(evenements, cles)` — vérifie un journal, tous les symptômes de la table 7.2.

### Merkle (`merkle.mjs`)

- `feuille(hash)` — L = SHA-256(0x00 ‖ D).
- `noeud(g, d)` — N = SHA-256(0x01 ‖ g ‖ d).
- `puissanceInferieure(n)` — plus grande puissance de deux strictement inférieure à n.
- `racineMerkle(hashes)` — racine RFC 6962, nulle pour une période vide.
- `preuveInclusion(m, hashes)` — chemin d'audit au format de `chemin.json`.
- `verifierInclusion(preuve)` — algorithme de §9.3.
- `preuveCoherence(m, hashes)` — PROOF(m, D[0..n-1]).
- `verifierCoherence(preuve)` — algorithme de §10.7, avec la raison d'un refus.

### Manifeste (`manifeste.mjs`)

- `DUREE_PERIODE` — 3600 secondes.
- `formeCanoniqueManifeste(m)` — C_M.
- `hacherManifeste(m)` — periodHash.
- `messageSignatureManifeste(m)` — P_SM ‖ C_M.
- `signerManifeste(m, graine)` — contenu de `manifeste.sig`.
- `verifierSignatureManifeste(m, sig, cle)` — vérifie la signature du manifeste.
- `construireManifeste(p)` — manifeste d'une période depuis les hash de ses événements.
- `ecartsManifeste(m)` — écarts au schéma et aux relations arithmétiques (P-1, P-4).
- `verifierContinuite(p, q)` — continuité de deux manifestes consécutifs (§10.3).
- `empreinteAncre(org, journal, empreinte)` — keccak256(org_id ‖ journal_id ‖ empreinte).
- `periodMeta(m)` — champs de `PeriodRegistry.PeriodMeta`.
- `RACINE_VIDE` — racine de la période vide.

### Point de contrôle (`point-de-controle.mjs`)

- `REGLES_SERIE` — noms des règles de série de §10.5.
- `corpsPoint(point)` — K', le point sans `sig`.
- `formeCanoniquePoint(point)` — C_K.
- `hacherPoint(point)` — checkpointHash.
- `messageSignaturePoint(point)` — P_SK ‖ C_K.
- `signerPoint(point, graine)` — signe le point.
- `verifierSignaturePoint(point, cle)` — vérifie la signature du point.
- `coherencePoint(treeSize, hashesPeriode)` — membre `consistency` vers le manifeste.
- `cleEnVigueur(parSeq, lastSeq, contexte?)` — clé en vigueur (règle 5) : celle de l'événement `last_seq`, sinon la règle de §10.1 sur `cles.json` à l'instant du point.
- `verifierSeriePointsDeControle(points, manifeste, evenements, cles)` — règles violées et erreurs d'une série.

### Attestation de périmètre (`attestation.mjs`)

- `TAILLE_MAX_PARTIE` — 4 Mio.
- `TAILLE_MAX_DOCUMENT` — 2 097 152 octets décodés.
- `VALIDITE_MAX_MS` — 366 jours.
- `VERIFICATIONS_PERIMETRE` — AT-1 à AT-7.
- `condenseAttestation(P)` — D_P = keccak256(P_P ‖ JCS(P)).
- `signerAttestation(cle, P)` — signature EIP-191 d'un signataire.
- `ecartsAttestation(P)` — relations qu'AT-1 ajoute au schéma.
- `verifierAttestationSignee(signee, jeu)` — AT-1 à AT-4 hors dossier.
- `verifierPartieAttestation(octets, contexte)` — AT-1 à AT-7, attestation retenue, avertissements.

### Dossier (`dossier.mjs`)

- `PARTIES_V0` — les douze parties v0.
- `PARTIE_POINTS_DE_CONTROLE` — la treizième partie facultative.
- `PARTIE_ATTESTATION_PERIMETRE` — la quatorzième partie facultative.
- `PARTIES_RESERVEES` — les cinq parties réservées à CT-4 et CT-5.
- `FICHIERS_DOSSIER` — noms de fichier qu'un index peut déclarer.
- `TAILLES_MAX` — limite de taille de chaque fichier d'un dossier (CT-6 EX-4.13).
- `PLAFOND_LECTURE` — 64 Mio, plafond de lecture en flux de `attestation-perimetre.json` (CT-6 EX-4.15).
- `RAISONS_ADMISES` — raisons de non-exécution qui laissent le dossier valide.
- `BORNE` — énoncé de la borne de §11.3.
- `DOC_TYPE_POINT` — `docType` de l'ancre d'un point au registre.
- `verifierDossier(fichiers, options?)` — tous les contrôles de §11.4 et le verdict (octets ou `FichierNonLu` par nom ; option `profondeurMax`).
- `indexerDossier(p)` — construit l'index `dossier.json`.

Point d'entrée `@noortrace/noyau/dossier-fichiers` (`src/dossier-fichiers.mjs`, seul
module qui lit des fichiers) :

- `lireRepertoireDossier(repertoire)` — lit `dossier.json` et les fichiers qu'un index peut déclarer, fichiers ordinaires seulement, chacun dans sa limite (`FichierNonLu` au-delà).
- `verifierRepertoireDossier(repertoire, options?)` — lit puis vérifie un dossier.

## Lectures de CT-1

Passages de CT-1 (et de CT-7 §7) que le texte ne tranche pas, et la lecture
que le paquet retient ; « aligné » signale un comportement corrigé pour suivre
un texte qui, lui, tranche.

- **Partie hors schéma mais exploitable** (§11.4 contre §11.5). §11.4 dit que
  les contrôles qui dépendent d'une partie contraire à son schéma sont « non
  exécutés », mais les vecteurs de §11.5 publient les cascades (E-1 et E-3,
  P-1 et P-4, E-1, E-7, E-8, C-2 et M-1…) : le contrôle porteur échoue, et les
  autres s'exécutent sur les champs bien typés qu'ils lisent. Une partie qui
  n'est pas un objet JSON, elle, n'est pas exploitée.
- **Analyse des `seq` d'un journal** (§7.2). Les doublons, retours en arrière
  et trous de `seq` se lisent sur tout le fichier, non couple par couple : un
  réordonnancement n'est pas aussi rapporté comme deux trous.
- **`cles.json` d'un journal** (§7.2, E-8). Son `org_id` et son `journal_id`
  sont comparés à ceux de chaque événement : un écart est un E-8 de cet
  événement, et un premier événement altéré ne masque plus les E-8 des autres
  (aligné : « un vérificateur de chaîne les rapporte tous »).
- **Règles de E-3** (tables 5.1 et 5.3). Appel d'outil : `policy.decision`
  parmi `autorise`, `a_approuver`, `refuse` ; `approval` non nul seulement
  avec `a_approuver` ; appel retenu : `a_approuver` et `approval` nul ; appel
  refusé : `refuse`, ou `a_approuver` avec une approbation `refuse` ou
  `expire` ; appel exécuté : `autorise`, ou `a_approuver` avec `approuve` ;
  appel retenu ou refusé : `effects` vide (§5.3 : « vide si aucun effet
  (appel retenu, refusé…) »). Autres sortes : `sans_objet`, `executee`,
  `intent` nul sauf échange, `approval` seulement pour une décision ;
  `result`, `duration_ms`, `is_error` selon la table de §5.3 ; décision :
  `arguments.value` = A ; rotation : `effects` de §8 règle 4 ; politique :
  `{ policy_version, policy_sha256 }`.
- **Décision d'approbation avec `effects` non vide** (E-3). Ni la table 5.1
  ni la table 5.3 ne fixent les effets d'une décision, et §5.3 ne nomme
  d'effets vides que pour l'appel retenu, refusé ou la lecture pure : E-3 ne
  la refuse pas.
- **A-4** (§11.4). La demande est le voisin dont le `hash` recalculé est
  `request_hash` ; aucun voisin ne l'étant, A-4 n'est pas exécutée
  (`piece_hors_dossier`, admise), même si un voisin est un appel retenu d'un
  autre hash ; `voisins.json` inexploitable : `prerequis_en_echec`.
- **Clé en vigueur d'un point quand `last_seq = 0`** (§10.5 règle 5, §10.1).
  Sans événement `last_seq` (journal encore vide, ou événement non fourni),
  la règle de §10.1 telle qu'écrite : la dernière clé annoncée dont
  `valid_from` ≤ `checkpoint_ts`, lue comme la clé de `cles.json` de plus grand
  `valid_from` ≤ cet instant, la dernière du fichier à égalité (aligné : la
  version précédente refusait tout `key_id`).
- **Partie facultative sans forme canonique** (§11.4). Une seule règle pour
  toutes les parties : un fichier sans forme canonique met E-2 en échec,
  `points-de-controle.json` compris (K-1 à K-9 non exécutées, sans raison
  admise ; aligné, l'écart se perdait sous K-1). Seule exception,
  `attestation-perimetre.json`, dont tout défaut, forme canonique comprise,
  est porté par AT-1 sans changer le verdict (§11.4, révision 0.4).
- **`dossier.json` à clé en double** (§11.4, CT-6 EX-4.12). C'est du JSON,
  sans forme canonique : E-2 en échec, les autres contrôles non exécutés ;
  l'entrée n'est pas « inutilisable », code réservé à un index absent ou qui
  n'est pas du JSON.
- **Partie déclarée présente mais absente** (§11.4 D-2, CT-6 EX-4.11). Échec
  de D-2 seul ; le contrôle qui porte la partie n'est pas exécuté (raison
  `partie_manquante`, non admise) et ceux qui en dépendent non plus, pour
  toutes les parties (aligné : `cles.json`, `approbations.json` et
  `points-de-controle.json` manquants mettaient aussi en échec E-8, A-1 ou
  K-1). Une entrée qui n'est pas un fichier ordinaire (répertoire, lien) n'est
  jamais ouverte et compte comme absente.
- **Partie au-delà de sa limite de taille** (CT-6 EX-4.11, EX-4.13). Échec
  du contrôle porteur ; D-2 ne compare pas son SHA-256, la limite interdisant
  de lire au-delà (sauf `attestation-perimetre.json`, hachée en flux jusqu'à
  64 Mio, EX-4.15). La limite de 16 Mio vaut pour les sept parties JSON v0
  autres que l'index (EX-4.13 dit « six »).
- **Profondeur d'imbrication** (§4). CT-1 n'en fixe aucune : aucune borne par
  défaut, ni à la lecture, ni à la forme canonique, ni dans `verifierDossier`
  (aligné : la borne de 256 refusait des événements conformes) ; la borne de
  128 de CT-6 EX-4.13 s'applique par l'option `profondeurMax`, et une partie
  qui la dépasse est inexploitable (contrôle porteur).
- **`org_id` ou `journal_id` nul** (§3, §5.2). « Non nul » n'est pas dans le
  schéma : pour un événement, c'est un échec de E-1 (validité de
  l'événement) ; pour un manifeste, de P-1 par `ecartsManifeste` (aligné,
  §10.1 : « ceux des événements »).
- **`org_id`, `journal_id` de l'index différents de l'événement** (D-1). D-1
  ne compare que `event.seq` et `event.hash` ; ces deux champs de l'index ne
  sont pas comparés.
- **Liaison de `tree_size`** (M-3, K-1, K-5). `chemin.tree_size` n'est lié au
  manifeste que par M-3 (= `count`) ; `consistency.first_size` et
  `second_size` ne sont liés au point et au manifeste que par K-5 ; K-1 ne lie
  que `checkpoint.tree_size` (`1 ≤ tree_size ≤ count`). Un écart n'est imputé
  qu'à ce contrôle.
- **K-1 quand P-1 échoue** (CT-6 EX-5.9). Le schéma de la partie est contrôlé
  quand même (défaut : K-1 en échec) ; sinon K-1 n'est pas exécutée,
  `prerequis_en_echec` (aligné).
- **Raison d'absence faite d'espaces** (D-2). « Raison non vide » et le
  schéma (`minLength` 1) sont satisfaits par une chaîne d'espaces : admise.
- **`approbations` absente avec une autre raison que « aucune approbation
  liée »** (§11.1 contre A-1). §11.1 décrit la raison qu'écrit l'exportateur ;
  A-1 ne porte que sur la présence de la partie, et D-2 sur une raison non
  vide : A-1 réussit quand `approval` est nul, quelle que soit la raison.
- **`policy.redaction = ""` avec une référence rédigée** (E-4). E-4 exige une
  valeur « non nulle » et le schéma admet la chaîne vide : E-4 réussit.
- **UTF-8 invalide, marque d'ordre d'octets, substitut CESU-8** (§3, §4).
  Un texte qui n'est pas de l'UTF-8 bien formé, ou qui commence par une
  marque d'ordre d'octets, n'est pas du JSON (§3 : « UTF-8 sans marque
  d'ordre d'octets ») : échec du contrôle porteur (E-1 pour
  `evenement.json`). Un substitut encodé en UTF-8 (`ED A0 80`) est un
  substitut isolé de §4 : E-2 (aligné ; il était imputé à E-1).
- **Plus de signatures que d'approbateurs** (E-5, E-9). E-9 dit « pour chaque
  `i`, l'adresse recouvrée de `signatures[i]` = `approvers[i]` » : `i`
  parcourt les signatures, et une signature sans `approvers[i]` met E-9 en
  échec en plus de E-5 (aligné) ; un approbateur sans signature relève de E-5
  seul (vecteur `invalide-signature-manquante`).
- **Dates d'AT-1** (§11.4 AT-1). « Dates existantes » couvre
  `validity.from`, `validity.until`, `issued_at`, et le `ts` et
  `approval.at` de l'événement d'inscription.
- **Parties réservées et ancres non nulles** (§11.4, CT-6). Leur vérification
  (T-, O-, R-, N-) est fixée par CT-6 : une partie réservée déclarée présente
  est rapportée non vérifiée (`non_executes_bloquants`, verdict invalide) ;
  une ancre non nulle de K-7, K-9 (et K-8 au-delà de l'empreinte et du
  `doc_type`) n'est pas exécutée (`verification_ct6_requise`) sans fonction
  de `options.verificateursAncres`.

## Dépendances

| Dépendance | Version | Licence | Usage |
|---|---|---|---|
| `@noble/curves` | 2.4.0 (exacte) | MIT | secp256k1 : signature et recouvrement d'adresse EIP-191 |
| `@noble/hashes` | 2.4.0 (exacte) | MIT | Keccak-256 |
| `node:crypto` | Node.js ≥ 22 | MIT (Node.js) | SHA-256, Ed25519 |

Aucune autre dépendance d'exécution. Pour les tests, la racine du dépôt porte
`fast-check` 4.10.2 (exacte, MIT) en dépendance de développement.

## Règle de salle blanche

Ce paquet est écrit d'après le seul texte de CT-1 (et de CT-7 §7, des passages
de CT-6 que CT-1 cite, des schémas et des données des vecteurs de
`spec/vecteurs/ct-1`). Ni son code ni ses tests n'ouvrent, ne cherchent ni
n'importent `scripts/lib/**`, `scripts/verify/**`, `scripts/vecteurs/**`,
`test/journal.test.js`, `test/verificateur.test.js`, `test/securite.test.js`,
les vérificateurs indépendants (`spec/vecteurs/*/verificateur-independant/`) ni
les répertoires `confrontation/`. Une ambiguïté du texte se tranche d'après le
texte et les vecteurs, et se consigne ; elle ne se tranche jamais en lisant
l'implémentation de référence, pour qu'un défaut de celle-ci ne se recopie pas
ici.

## Tests

Depuis la racine du dépôt, après `npm ci` :

```sh
npx hardhat --config hardhat.config.mjs test test/noyau-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/noyau-proprietes.test.js
npx hardhat --config hardhat.config.mjs test test/noyau.test.js
```

- `test/noyau-vecteurs.test.js` rejoue chaque vecteur de `spec/vecteurs/ct-1`
  contre son `attendu.json` et vérifie par un inventaire que chaque fichier de
  données des familles est consommé ;
- `test/noyau-proprietes.test.js` est l'entrée TU-12 du plan de tests (cinq
  propriétés, fast-check, graine constante, 200 exécutions) ; un échec se
  rejoue par le couple `seed`/`path` imprimé ;
- `test/noyau.test.js` couvre l'API publique et ses refus, et l'exemple de
  référence de CT-1, lu dans le texte de la spécification.
