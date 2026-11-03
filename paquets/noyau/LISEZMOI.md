# @noortrace/noyau

Bibliothèque noyau de NOORTRACE, étape 1 de la phase 2 : forme canonique,
hachage, signatures, chaînage, arbre de Merkle, manifeste, point de contrôle
et dossier de preuve, tels que les fixe la spécification normative
[CT-1 version 0.5](../../spec/CT-1-evenements-et-formats.md) (avec la section 7
de [CT-7](../../spec/CT-7-securite-et-conformite.md), qui fait foi pour
l'attestation de périmètre, et les règles de la section 5.6 de
[CT-6 version 0.4](../../spec/CT-6-verificateur.md) que CT-1 reprend).

Le paquet est écrit à neuf depuis le seul texte de la spécification ; il ne
reprend rien de l'implémentation de référence qui a produit les vecteurs
(`scripts/lib/journal.mjs`). Les vecteurs de `spec/vecteurs/ct-1` sont le juge
entre les deux : la bibliothèque les rejoue tous, avec les vérifications de
CT-1 des dossiers de `spec/vecteurs/ct-6` (`test/noyau-vecteurs.test.js`).

## Ce que fait le paquet

- lit le JSON strictement (UTF-8 bien formé sans marque d'ordre d'octets ;
  clé en double, substitut isolé, nombre non entier ou hors de l'intervalle
  sûr : refus de forme canonique, E-2) et calcule la forme canonique JCS v0,
  avec la borne de profondeur de CT-1 §4 règle 7 (128, racine comprise) par
  défaut, sans récursion : une imbrication arbitraire n'épuise jamais la pile ;
  l'option `profondeurMax` fixe une autre borne (`Infinity` : aucune) ;
- décode les horodatages RFC 3339 à la milliseconde sans jamais renormaliser
  une date inexistante ; n'admet que les entiers sûrs et l'hexadécimal minuscule
  préfixé ;
- hache et signe événements, manifestes et points de contrôle (SHA-256 et
  Ed25519 « pur » avec les préfixes de domaine de l'annexe B), vérifie Ed25519
  sans cofacteur en refusant S non réduit, les encodages non canoniques et les
  clés de petit ordre ; signe et recouvre les signatures EIP-191 des
  approbateurs (règle « s bas », v ∈ {27, 28}) ;
- vérifie un journal selon la règle exacte de CT-1 §7.2 (chaque événement pour
  lui-même et son origine, puis la suite des `seq` sur tout le fichier, puis
  chaque couple dans l'ordre du fichier) en rapportant tous les symptômes de
  la table 7.2, avec leurs types ;
- construit l'arbre de Merkle RFC 6962 (racine nulle de la période vide), les
  preuves d'inclusion et de cohérence, et les vérifie par les algorithmes de la
  RFC 9162 reproduits dans CT-1 ;
- hache, signe et enchaîne les manifestes (continuité, PeriodMeta, empreinte
  d'ancre), hache et signe les points de contrôle, vérifie une série de points
  contre son manifeste avec les noms de règles de §10.5, règles violées et
  règles non évaluées faute d'événement ;
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
qu'après `lstat`, s'il est ordinaire (puis sans suivre de lien ni attendre, et
seulement si le descripteur désigne le même fichier : CT-6 EX-4.17), et ne le lit
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
fixés par CT-6). Comme CT-1 §11.4 (révision 0.5) le demande à un vérificateur
de CT-1 seul, une partie réservée déclarée présente est rapportée comme non
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
- `chaineNonVide(valeur)` — chaîne qui contient un caractère autre qu'un blanc (CT-1 §3, révision 0.5 : White_Space et U+FEFF).

### JSON strict et JCS v0 (`json-strict.mjs`)

- `CODES_FORME_CANONIQUE` — codes d'erreur relevant de E-2.
- `PROFONDEUR_V0` — 128, profondeur d'imbrication maximale d'un texte du format v0 (CT-1 §4, règle 7), borne par défaut.
- `PROFONDEUR_CT6` — 128, celle de CT-6 EX-4.13, égale à `PROFONDEUR_V0`.
- `depasseProfondeur(valeur, profondeurMax?)` — une valeur en mémoire est plus profonde que la borne (comptage de CT-1 §4, règle 7).
- `ErreurJson` — erreur de lecture ou de forme canonique (`code`, `formeCanonique`).
- `decoderUtf8(octets)` — décode de l'UTF-8 bien formé sans marque d'ordre d'octets ; un substitut encodé (CESU-8) est un `substitut_isole` (E-2).
- `analyserJson(source, options?)` — lecture stricte et itérative (refus de E-2 ; options pour le document de politique ; `profondeurMax`, 128 par défaut, aucune en nombres libres).
- `chaineBienFormee(s)` — aucune moitié de substitut isolée.
- `jcs(valeur, options?)` — forme canonique JCS v0, itérative, structure cyclique refusée (`profondeurMax`, 128 par défaut).
- `jcsOctets(valeur, options?)` — forme canonique en UTF-8.
- `canoniserTexte(source, options?)` — forme canonique d'un texte JSON, ou null s'il est refusé.
- `egaliteJson(a, b)` — égalité de deux valeurs JSON, membre pour membre, itérative.
- `lireJournal(source, options?)` — lit un fichier de journal (tableau d'événements) ; un élément sans forme canonique reste lisible et marqué (E-2 pour lui, hash incalculable, CT-1 §7.2).
- `formeCanoniqueAbsente(valeur)` — motif du défaut de forme canonique d'un événement lu par `lireJournal`, ou null.

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
- `LANCEUR_ENREGISTREUR` — `"noortrace-enregistreur"`, `delegation.launched_by` d'une rotation ou d'un changement de politique (E-3).
- `ecartsSorte(e)` — écarts à la règle exacte de E-3 (CT-1 §5.3, révision 0.5).
- `controlerEvenement(e, contexte?)` — E-1 à E-11 et le hash recalculé (événement plus profond que 128 : E-1).
- `hashRecalcule(e)` — hash recalculé, ou null.
- `nouvelleCle(e)` — `new_key_id` d'une rotation, sinon null.

### Chaînage (`chainage.mjs`)

- `ORDRE_CONTROLES` — ordre de rapport des contrôles de §11.4.
- `trierControles(ids)` — trie des identifiants dans cet ordre.
- `verifierJournal(evenements, cles)` — vérifie un journal, tous les symptômes de la table 7.2, dans l'ordre de la règle exacte de §7.2.

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
- `verifierSeriePointsDeControle(points, manifeste, evenements, cles)` — règles violées (`rules_failed`), règles non évaluées (`rules_not_evaluated`) et erreurs d'une série.

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
- `VERIFICATION_CT6_NON_EXECUTEE` — détail d'une vérification de CT-6 non exécutée par la bibliothèque (raison `prerequis_en_echec`, CT-1 §11.4).
- `DOC_TYPE_POINT` — `docType` de l'ancre d'un point au registre.
- `verifierDossier(fichiers, options?)` — tous les contrôles de §11.4 et le verdict (octets ou `FichierNonLu` par nom ; option `profondeurMax`, 128 par défaut).
- `indexerDossier(p)` — construit l'index `dossier.json`.

Point d'entrée `@noortrace/noyau/dossier-fichiers` (`src/dossier-fichiers.mjs`, seul
module qui lit des fichiers) :

- `lireRepertoireDossier(repertoire)` — lit `dossier.json` et les fichiers qu'un index peut déclarer, fichiers ordinaires seulement, chacun dans sa limite (`FichierNonLu` au-delà).
- `verifierRepertoireDossier(repertoire, options?)` — lit puis vérifie un dossier.

## Règles de CT-1 révision 0.5 appliquées

La section « Lectures de CT-1 » des versions précédentes consignait les
passages que CT-1 0.4 ne tranchait pas. La révision 0.5 de CT-1 et la
révision 0.4 de CT-6 les tranchent dans le texte ; le paquet applique ces
règles, que voici avec leur renvoi.

| Règle | Renvoi | Module |
|---|---|---|
| UTF-8 mal formé, marque d'ordre d'octets : pas du JSON (contrôle porteur, E-1 pour `evenement.json`) ; substitut écrit en octets (`ED A0 80`) : E-2 | CT-1 §3, §4 règle 3 ; CT-6 EX-4.16 | `json-strict.mjs` |
| Chaîne non vide : au moins un caractère hors des blancs (White_Space et U+FEFF) | CT-1 §3 | `conventions.mjs` |
| Profondeur d'au plus 128, racine comprise, par défaut ; au-delà, partie inexploitable (contrôle porteur) ; événement d'un journal plus profond : E-1 | CT-1 §4 règle 7 ; CT-6 EX-4.13, EX-4.16 | `json-strict.mjs`, `controles-evenement.mjs` |
| E-3, règle exacte : appel d'outil (décision, statut, `approval`, effets vides d'un appel retenu ou refusé) ; échange ; décision (même forme canonique que `A`, effets vides) ; rotation et changement de politique (`delegation.launched_by = "noortrace-enregistreur"`, effets de §8 règle 4, `policy_version` de 1 à 128 caractères) | CT-1 §5.3 ; CT-6 EX-5.17 | `controles-evenement.mjs` |
| E-4 : `policy.redaction` chaîne non vide | CT-1 §5.3, §11.4 | `controles-evenement.mjs` |
| Journal : trois temps (E-1 à E-11 puis origine ; insertions, suppressions, réordonnancements sur tout le fichier, parmi les `seq` entiers ; couples), `cles.json` comparé à chaque événement, types `schema`, `format`, `sorte`, `redaction`, `approbation`, `reference`, `modification`, `signature`, `approbateur`, `rotation`, `validite_cle`, `cles`, `origine`, `insertion`, `suppression`, `reordonnancement`, `rupture`, `horodatage`, `journal`, `cle` | CT-1 §7.2 | `chainage.mjs` |
| Clé en vigueur d'un point sans l'événement `last_seq` : clé de plus grand `valid_from` ≤ `checkpoint_ts`, la dernière de `keys` à égalité ; aucune : règle violée | CT-1 §10.5 règle 5 | `point-de-controle.mjs` |
| Série de points : `root` et `last_hash` évaluées point par point ; événement non fourni : non évaluées (`piece_hors_dossier`), fourni sans forme canonique : `prerequis_en_echec`, jamais violées ni remplacées par 32 octets nuls ; `rules_not_evaluated` au rapport ; série valide si les deux listes sont vides | CT-1 §10.5 | `point-de-controle.mjs` |
| Raison d'absence d'une partie : chaîne non vide (blancs : D-2 ; chaîne vide : D-1 par le schéma) | CT-1 §11.1, D-2 | `dossier.mjs` |
| `approval` nul : partie déclarée absente avec la raison exacte « aucune approbation liée » ; sinon A-1 en échec, A-2 à A-4 `prerequis_en_echec` | CT-1 §11.1, A-1 ; CT-6 EX-5.16 | `dossier.mjs` |
| Contrôle porteur de chaque partie ; cinq cas de partie inexploitable ; contrôles qui lisent une partie inexploitable non exécutés sans raison admise, sauf échec sur les autres parties | CT-1 §11.4 ; CT-6 EX-4.11, EX-5.13 | `dossier.mjs` |
| Partie contraire à son schéma : porteur en échec, partie exploitable ; relation à terme absent, mal typé ou incalculable (un `seq` en chaîne, le hash d'un voisin qui n'est pas un objet, une date inexistante) : le contrôle qui l'évalue échoue | CT-1 §11.4 | `dossier.mjs`, `controles-evenement.mjs` |
| Exceptions : `dossier.json` (D-1 seul, ou E-2 seul pour une clé en double ; absent ou pas du JSON : entrée inutilisable) ; `cles.json` exploitable si et seulement si la première partie de E-8 réussit, impossible sans `evenement.json` exploitable ; `points-de-controle.json` (K-1 en échec ou non exécutée : K-2 à K-9 `prerequis_en_echec`) | CT-1 §11.4 ; CT-6 EX-4.12 | `dossier.mjs` |
| Statut de E-1 à E-11 sur plusieurs événements : en échec pour un événement ; sinon non exécutée si `evenement.json` est inexploitable ou si elle ne l'est pas pour un événement ; sinon réussie | CT-1 §11.4 | `dossier.mjs` |
| `evenement.json` inexploitable : D-1, E-2, P-1, P-2, P-5, C-, M-1, M-3, A-, K- non exécutées, sauf échec ; P-1 jamais réussie | CT-1 §11.4 ; CT-6 EX-5.14, EX-5.15 | `dossier.mjs` |
| D-1 compare `event.seq`, `event.hash`, `org_id`, `journal_id` | CT-1 §11.4 ; CT-6 EX-5.14 | `dossier.mjs` |
| Partie déclarée présente sans fichier ordinaire : D-2 seule ; au-delà de sa limite : porteur en échec, SHA-256 non comparé ; limites de CT-6 EX-4.13 (sept parties JSON v0 à 16 Mio) | CT-1 §11.4 ; CT-6 EX-4.11, EX-4.13, EX-4.17 | `dossier.mjs`, `dossier-fichiers.mjs` |
| E-9 : une signature sans `approvers[i]` échoue, en plus de E-5 ; `approvers` ou `signatures` qui n'est pas un tableau : E-9 en échec | CT-1 §11.4 ; CT-6 EX-5.19 | `controles-evenement.mjs` |
| A-4 : la demande est le voisin dont le hash recalculé égale `request_hash` ; aucun : `piece_hors_dossier` ; `voisins.json` inexploitable : `prerequis_en_echec` | CT-1 §11.4 ; CT-6 EX-5.18 | `dossier.mjs` |
| K-1 contrôle le schéma de la partie même quand P-1 n'a pas réussi ou que `evenement.json` est inexploitable ; K-1 ne lie que `tree_size` au manifeste, K-5 la preuve de cohérence, M-3 `chemin.tree_size` | CT-1 §11.4 ; CT-6 EX-5.9 | `dossier.mjs` |
| K-6 avec `voisins.json` inexploitable : non exécutée, `prerequis_en_echec` (et non `piece_hors_dossier`) | CT-1 §11.4 ; CT-6 EX-5.9 | `dossier.mjs` |
| `points-de-controle.json` sans forme canonique : E-2, K-1 à K-9 non exécutées | CT-1 §11.4 ; CT-6 EX-5.20 | `dossier.mjs` |
| Partie réservée présente, ancre non nulle : jamais « valide » pour un vérificateur de CT-1 seul | CT-1 §11.4 | `dossier.mjs` |
| AT-1 : dates de l'inscription ; AT-5 et AT-6 exigent E-1 et E-2 réussies sur l'événement prouvé | CT-1 §11.4 | `attestation.mjs` |
| Lecture d'un répertoire : fichiers ordinaires seulement (`lstat`, ouverture sans suivre de lien ni attendre, même périphérique et même inode sur le descripteur) | CT-1 §11.4 cas (a) ; CT-6 EX-4.17 | `dossier-fichiers.mjs` |

Décisions du 3 novembre 2026, complétées en place dans CT-1 révision 0.5 et
CT-6 révision 0.4, que le paquet applique aussi :

| Règle | Renvoi |
|---|---|
| « Sauf échec » : la part de la règle qui ne lit pas la partie inexploitable est évaluée ; le contrôle échoue si elle ne tient pas, sinon il n'est pas exécuté, jamais réussi | CT-1 §11.4 ; CT-6 EX-5.15 |
| K-6 se juge sur l'événement prouvé quand `last_seq` est son `seq`, quel que soit l'état de `voisins.json` ; `voisins.json` inexploitable ne donne `prerequis_en_echec` que si `last_seq` désigne un voisin | CT-1 §10.5, K-6 ; CT-6 EX-5.9 |
| `approval` nul et `approbations.json` déclarée présente : A-1 échoue, que le fichier existe ou non (D-2 en plus s'il manque) | CT-1 §11.4 cas (a), A-1 ; CT-6 EX-4.11, EX-5.16 |
| Vérification de CT-6 non exécutée : `prerequis_en_echec`, détail « vérification de CT-6 non exécutée par ce vérificateur » (`VERIFICATION_CT6_NON_EXECUTEE`) ; partie réservée non vérifiée quelle que soit sa taille | CT-1 §11.4 ; CT-6 EX-4.2 |
| Série : un événement manque et un autre est sans forme canonique, `prerequis_en_echec` ; une entrée par couple (règle, raison) ; ordre des noms de règle, puis `prerequis_en_echec` avant `piece_hors_dossier` | CT-1 §10.5 |
| Série : sans `cles.json`, `signature`, `validite_cle` et (sans l'événement `last_seq`) `cle_en_vigueur` non évaluées (`piece_hors_dossier`) ; `cles.json` qui ne passe pas la première partie de E-8 lue sans événement, `prerequis_en_echec` | CT-1 §10.5 |
| Noms de règle fermés : en-tête ou schéma → `period_start` ; racine nulle à tort → `root` ; `tree_size > count` → `last_seq` ; clé absente → `signature` (et `cle_en_vigueur`) | CT-1 §10.5 |
| Journal : `ts` qui n'est pas une date existante, symptôme `horodatage` ; réordonnancement lu parmi les `seq` entiers ; hash incalculable du précédent (événement sans forme canonique, lu par `lireJournal`), `rupture` ; un événement sans forme canonique n'a que E-2 ; `seq` d'un symptôme nul quand il n'est pas un entier | CT-1 §7.2, §11.4 cas (d) |
| Voisin absent, ou présent ni objet ni `null` : C-1, C-2, C-3, P-3 en échec, E-1 pour lui s'il est présent ; ni demande d'A-4 ni événement de K-6 | CT-1 §11.4 ; CT-6 EX-5.13 |
| `approval` ni nul ni objet : E-1, A-1 à A-4 en échec ; `execution.tool` qui n'est pas une chaîne : E-1 et E-3 ; origine de C-2 sur chaque événement du dossier | CT-1 §11.4 |
| Document de politique d'une inscription : même borne de 128 et même comptage, nombres libres | CT-1 §4 règle 7 ; CT-6 EX-4.16 |
| Entrée inutilisable : `type_erreur` (`dossier_illisible`, `taille_depassee`), l'`error_kind` de `attendu.json` | CT-1 §11.5 ; CT-6 EX-4.12, EX-4.15 |

## Lectures qui restent

- **Racine nulle d'un point de `tree_size ≥ 1`** (§10.5). Le schéma du point
  la refuse (son `allOf`), et le texte range les défauts de schéma sous
  `period_start` mais la racine nulle sous `root`. Le paquet tient un point
  dont le seul défaut de schéma est cette racine pour conforme à son en-tête
  et viole `root` seule.

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
`spec/vecteurs/ct-1` et des dossiers de `spec/vecteurs/ct-6`). Ni son code ni ses tests n'ouvrent, ne cherchent ni
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
  données des familles est consommé ; il compare aussi, pour chaque dossier de
  `spec/vecteurs/ct-6/dossiers`, le statut et la raison des vérifications de
  CT-1 (D-1 à A-4, K-1 à K-9) à son `attendu.json` ;
- `test/noyau-proprietes.test.js` est l'entrée TU-12 du plan de tests (cinq
  propriétés, fast-check, graine constante, 200 exécutions) ; un échec se
  rejoue par le couple `seed`/`path` imprimé ;
- `test/noyau.test.js` couvre l'API publique et ses refus, l'exemple de
  référence de CT-1, lu dans le texte de la spécification, et chaque règle de
  la révision 0.5 de CT-1 (bloc « révision 0.5 de CT-1, révision 0.4 de
  CT-6 »), en réussite et en échec.
