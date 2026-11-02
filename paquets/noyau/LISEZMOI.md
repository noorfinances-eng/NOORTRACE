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
  hors de l'intervalle sûr : refus) et calcule la forme canonique JCS v0 ;
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
- `PROFONDEUR_MAX` — imbrication maximale admise.
- `ErreurJson` — erreur de lecture ou de forme canonique (`code`, `formeCanonique`).
- `decoderUtf8(octets)` — décode de l'UTF-8 bien formé sans marque d'ordre d'octets.
- `analyserJson(source, options?)` — lecture stricte (refus de E-2 ; options pour le document de politique).
- `chaineBienFormee(s)` — aucune moitié de substitut isolée.
- `jcs(valeur)` — forme canonique JCS v0.
- `jcsOctets(valeur)` — forme canonique en UTF-8.
- `canoniserTexte(source)` — forme canonique d'un texte JSON, ou null s'il est refusé.
- `egaliteJson(a, b)` — égalité de deux valeurs JSON, membre pour membre.

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
- `cleEnVigueur(parSeq, lastSeq)` — clé en vigueur (règle 5).
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
- `RAISONS_ADMISES` — raisons de non-exécution qui laissent le dossier valide.
- `BORNE` — énoncé de la borne de §11.3.
- `DOC_TYPE_POINT` — `docType` de l'ancre d'un point au registre.
- `verifierDossier(fichiers, options?)` — tous les contrôles de §11.4 et le verdict.
- `indexerDossier(p)` — construit l'index `dossier.json`.

Point d'entrée `@noortrace/noyau/dossier-fichiers` (`src/dossier-fichiers.mjs`, seul
module qui lit des fichiers) :

- `lireRepertoireDossier(repertoire)` — lit `dossier.json` et les fichiers qu'un index peut déclarer.
- `verifierRepertoireDossier(repertoire, options?)` — lit puis vérifie un dossier.

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
