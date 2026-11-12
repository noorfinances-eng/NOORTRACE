# Interfaces du composant d'ancrage (CT-5) : contrat final du paquet

Ce document est le contrat du paquet `@noortrace/ancrage` (étape 5 de la
phase 2) : les cinq sous-modules (`src/rfc3161/`, `src/ots/`,
`src/planificateur/`, `src/registre/`, `src/serveur-interne/`), le composant
temps réel (`src/composant.mjs`), l'outil `bin/noortrace-ancrage`,
l'exportateur (`src/exportateur.mjs`) et ce que l'intégration à
l'enregistreur (`paquets/enregistreur/src/ancrage-demon.mjs`) fournit. Il a
d'abord servi aux développeurs qui ont écrit les sous-modules en parallèle et
sans se lire ; il a ensuite été aligné sur le code livré, écarts retenus
compris (assemblage, corrections de la relecture adversariale, révisions
CT-5 0.4 et 0.5, CT-6 0.5) : il décrit exactement le code. La spécification est
normative ; ce document ne la remplace pas : quand il nomme une règle (EX-,
AN-, T-, O-, RG-, CP-, OP-), le texte de la règle fait foi. Les lectures de
passages ambigus sont dans `LISEZMOI.md`, section « Lectures ».

Règles communes :

1. **Le schéma `spec/schemas/planificateur-ancrage-v0.schema.json` est le
   contrat entre le planificateur et les clients.** Les clients rendent des
   objets exactement conformes au `data` d'un `$defs/evenement_entree` de
   leur type ; le planificateur émet des `$defs/action_attendue` ; la file
   est faite de `$defs/demande`. Aucun champ hors schéma, aucune valeur hors
   énumération. Trois entrées que le schéma ne porte pas (retrait de
   `qualified`, révocation constatée après coup, résultat de client refusé
   par le schéma) sont des méthodes du planificateur (rubrique C : `relever`,
   `revoquer`, `rejeter`), jamais des entrées de trace.
2. **Horloge et aléa injectés partout** : aucun module ne lit `Date.now()`,
   `performance.now()`, `setTimeout` ni `crypto.randomBytes` ; il reçoit un
   objet `horloge = { murale(): number (ms UTC), monotone(): number (ms) }`,
   complété pour le composant de `programmer(delaiMs, fn) → annuler()`, et une
   fonction `aleatoire(n): Uint8Array`. Les binaires (`bin/`) branchent
   `Date.now`, `performance.now`, `setTimeout` et `crypto.randomBytes` ; les
   tests injectent une horloge réglable. Les seuls minuteurs de `src/` sont
   les délais de transport (`AbortSignal.timeout`, `timeout` de `http.request`),
   bornes d'entrée-sortie fixées par l'appelant.
3. **Rien n'est réencodé** : requêtes, réponses, jetons, preuves `.ots`,
   réponses JSON-RPC sont conservés et comparés sur leurs octets (CT-6
   EX-13.3, CT-4 CP-6).
4. **Aucun secret** dans un enregistrement, une ligne de file, une ligne de
   journal, une trace, un message d'erreur (AN-43, EX-5.13). Les secrets sont
   résolus par l'appelant (CT-2 §15.2) et remis en octets.
5. **Instants** : en interne, millisecondes UTC (entiers) ; dans les fichiers
   et les objets du schéma, horodatages RFC 3339 UTC à trois décimales
   (CT-1 §3), sauf `gen_time` (secondes, forme du schéma) et `period_start`
   (secondes, entier).
6. **Statuts des vérifications** : `reussi`, `echoue`, `non_execute` (CT-6
   EX-6.1), partout.
7. **Dépendances** : `@noortrace/noyau` (JCS, hachage, Ed25519, keccak, point
   de contrôle, manifeste, dossier, schémas) ; `@noble/curves` et
   `@noble/hashes` 2.4.0 pour secp256k1 (`src/registre/` seulement) ; `node:crypto`
   pour RSA, ECDSA P-256/384/521, X.509 (aide à la vérification des
   signatures ; la lecture stricte des structures est faite par les lecteurs
   DER bornés) ; rien d'autre.
8. **Disposition** : `src/<sous-module>/index.mjs` exporte ce que sa
   rubrique nomme ; `src/index.mjs` réunit les cinq, le composant et
   l'exportateur. `src/rfc3161/` possède `der.mjs` (lecteur DER borné) ;
   `src/serveur-interne/` possède son propre encodeur (`der-ecriture.mjs`) et
   son propre lecteur (`der-lecture.mjs`) : les deux lecteurs sont gardés
   (voir `LISEZMOI.md`, « Deux lecteurs DER »).

## A. Client RFC 3161 et vérification à l'acquisition (`src/rfc3161/`)

Sections : CT-5 §5 (EX-5.1 à EX-5.16, AN-5 à AN-15), §10.2 (fiche de
prestataire, EX-10.6, AN-54), §11 (EX-11.4, AN-55 à AN-58) ; CT-6 §9 (T-1 à
T-10, profil DER §9.3, identifiants §9.4), §12.2 et §12.4 (forme des ancres :
`anchor_certificates` et `accepted_policies` jouent le rôle de
`tsa_authorities[]`), §13.1, §13.4 (EX-13.14 à EX-13.19), §15.1 et §15.4
(bornes, algorithmes refusés).

```js
import {
  construireRequete, relireRequete,            // EX-5.1, AN-5
  tirerNonce,                                  // EX-5.3, AN-6
  lireReponse, lireJeton, lireTstInfo,         // AN-8 : TimeStampResp → { status, failureInfo, token } ; structure du jeton (T-1)
  verifierJeton,                               // T-1 à T-9 (CT-6 §9.5), avec ancres et politiques du prestataire
  verifierRevocation, capturerCrls,            // T-10 différée (EX-5.10 étape 10 ; CT-6 EX-13.12, EX-13.17) et capture des CRL
  classerErreur, lireRetryAfter, bornerRetryAfter, attenteReprise, attenteTransitoire, RETRY_AFTER_MAX_S, // EX-5.12, AN-11 ; EX-8.9 (table unique de l'attente de reprise)
  acquerir,                                    // EX-5.10 étapes 1 à 9 : une tentative complète, réseau compris
  DepotAncres, choisirPromu,                   // EX-5.14 : fichiers d'une période, acquisitions.ndjson ; EX-5.8
  copieAutonome,                               // copie d'une valeur JSON relue, chaînes recopiées (aucune tranche d'un texte de fichier)
  construireFiche, verifierFiche, epreuveAcceptation, // EX-10.6, AN-54 ; épreuve d'acceptation EX-11.4, AN-57
  transportHttps, controlerUrl,                // EX-5.5
  lireCertificatPem, lireCertificat, lireCrl, lireCrlDer, decoderPem, certificatVersPem, crlVersPem, pointsDistributionCrl, urisOcsp, // CT-6 §9.3, N-1
  parcourirDer,                                // lecteur DER borné : parcours d'une valeur (structures des attributs signés, EX-9.7)
} from "@noortrace/ancrage/rfc3161";
```

Contrat :

- `construireRequete({ imprint: hex32, hash: "sha256", nonce: bigint|hex8, policy_oid: string|null })`
  rend `{ octets: Uint8Array, sha256: hex32 }`, octets exacts d'EX-5.1 ;
  lève `ErreurRequete` sur toute forme refusée (AN-5, AN-6). `relireRequete(octets)`
  relit avec le lecteur borné et rend les champs ; une relecture non
  identique à l'entrée est une erreur (AN-5).
- `tirerNonce(aleatoire)` rend un `bigint` dans `[1, 2^64 − 1]` (tirage nul
  rejoué). Le réemploi d'un nonce dans un même journal est contrôlé par
  `DepotAncres.nonceConnu(nonce)` sur `acquisitions.ndjson`.
- `acquerir({ prestataire, imprint, objet, nonce, attemptId, attempt, periodStart, deadlineIndex, horloge, aleatoire, depot, transport, fraicheur, retry, tardivesAvant, k, premier408 })`
  exécute EX-5.5 et EX-5.10 étapes 1 à 9 et rend `{ data, enregistrement,
  fichiers, verification, classement, outcome, code, warnings, requete,
  reponse, jeton, erreurEcriture }` : `data` est **exactement** le `data`
  d'une entrée `reponse_rfc3161` du schéma (`request_id`, `attempt`,
  `transport`, `http_status`, `pki_status`, `failure_info`, `retry_after_s`,
  `nonce_in_response`, `imprint_matches`, `checks_passed`, `gen_time`,
  `accuracy_s`, `token_sha256`, `token_size`, `content_type`, `body_size`,
  `policy_check`) ; `enregistrement` est la ligne d'EX-5.13 ; `fichiers` les
  chemins écrits ; `verification` le résultat de `verifierJeton` (chemin
  retenu par T-7, autorité, identité, `tstInfo`), dont le composant se sert
  pour la T-10 différée. `attempt` (rang), `periodStart` et `deadlineIndex`
  servent le répertoire et l'enregistrement ; `fraicheur` et `retry` sont les
  objets de la configuration ; `tardivesAvant` compte les réponses tardives
  consécutives déjà reçues (EX-5.11 : la troisième est promue avec
  avertissement) ; `k` le nombre d'échecs transitoires consécutifs chez ce
  prestataire, celui-ci compris ; `premier408` dit si c'est le premier 408 de
  la demande chez lui (EX-8.9). Une `url` refusée par EX-5.5 (schéma,
  `http://` hors du rôle `interne`, `basic` hors TLS) lève `ErreurTransport`
  (`code: "url"`) : configuration qu'AN-1 refuse, jamais une tentative. Une
  écriture impossible (étape 9) rend `erreurEcriture` et un `outcome`
  `echec_transitoire` de code `ecriture` : l'appelant rejoue l'écriture sans
  renvoyer la requête (EX-5.12). Un statut HTTP hors de `[100, 599]` n'est pas
  une réponse HTTP : `transport: erreur_transport`, `http_status` nul, code
  `http_hors_bornes` (permanent) dans l'enregistrement ; un `Content-Type`
  vide vaut absent ; un corps dont le jeton ne se lit pas est
  `reponse_illisible` (le `.tsr` est écrit, aucun `.der`) ; une réponse 200
  d'un autre `Content-Type` est `type_contenu`.
- `transport` est injectable : `{ envoyer({ url, octets, entetes, delaiMs, auth, tls, role, serveurInterne }) → { status, entetes, corps, tronque } ; obtenir(url, delaiMs) → { status, entetes, corps } }` ;
  `serveurInterne` (vrai quand le prestataire porte `serveur_interne: true`,
  que le composant pose hors production pour le principal non qualifié, CT-5
  révision 0.9) fait admettre `http://` vers une adresse locale comme pour le
  rôle `interne` ; sans lui, `controlerUrl` refuse `http://` hors du rôle
  `interne` ;
  `transportHttps({ ca, agent, agentHttp })` applique EX-5.5 : TLS 1.2 au moins
  avec vérification du certificat du serveur (`ca` : autorités de confiance
  supplémentaires, pour un prestataire d'essai), `POST`, en-têtes exacts,
  `Content-Length`, `Accept`, authentification `basic` (sur TLS seulement) ou
  `certificat_client` (`auth.secret` : clé et certificat PEM concaténés),
  en-tête de corrélation, corps de réponse borné à 128 Kio, `http://` admis
  pour le seul rôle `interne` vers une adresse locale (AN-1, règle 4) ;
  `obtenir` est un `GET` borné pour les CRL. `min_interval_ms` entre deux
  requêtes au même prestataire est tenu par le planificateur (EX-8.7).
- `prestataire` est un élément de `rfc3161.providers[]` d'`ancrage-v0`
  **résolu** : `auth.secret` remplacé par ses octets par l'appelant (CT-2
  §15.2) ; le client ne lit ni fichier ni variable d'environnement.
- `verifierJeton({ octets, imprintAttendue, ancres: { certificatsPem[], politiquesAdmises|null } | fichier d'ancres CT-6 | null, aGenTime: true })`
  rend `{ checks: { "T-1"…"T-9": "reussi"|"echoue"|"non_execute" }, raisons, details, avertissements (AV-T-1 à AV-T-3), jeton, tstInfo: { genTime (ms), genTimeTexte, accuracy, accuracyUs, upperBoundMs, serialNumber, policy, nonce, tsuSubject }, certificatSignataire, chemin: [certificats lus], autorite, identite, faits }` ;
  T-11 n'est jamais exécutée ici (EX-5.9) ; `aGenTime` doit être vrai (T-7 à
  `genTime`, EX-9.13). Les algorithmes admis et les bornes des clés sont ceux
  de CT-6 §9.5 (T-5), EX-9.23 et EX-9.24. T-1 lit chaque certificat selon
  CT-6 §9.3, `SubjectPublicKeyInfo` (dont la `RSAPublicKey`) et valeurs des
  extensions connues comprises, et chaque valeur d'attribut signé ou non
  signé (`parcourirDer`) : une longueur non minimale ou une structure fausse
  met T-1 en échec, non T-5 ni T-8 (CT-6 EX-9.7, révision 0.5 ; vecteurs
  `t1-cle-longueur-non-minimale`, `t1-extension-mal-formee`).
- `verifierRevocation({ chemin, autorite: { nom, certificat, identite }|null, crls, crlsJeton, declarations, aInstant })`
  rend `{ statut, raison, detail, preuves, avertissements, revocations }` (T-10) ;
  `capturerCrls({ chemin, transport, horloge, delaiMs, apresInstant })` capture
  les CRL aux points de distribution des certificats du chemin et rend, par
  certificat, `{ certificate_sha256, sources, ocsp, crl, pem, erreur, captured_at }`
  (une CRL dont `thisUpdate` précède `apresInstant` est rendue avec `erreur` :
  `crl_indisponible`, réessayée).
- `classerErreur({ code | httpStatus, retryAfter, maintenantMs, pkiStatus, failureInfo, retry, k, premier408 })`
  rend `{ classe: "transitoire"|"permanente"|null, attenteMs, raisonAttente, alerte: "aucune"|"alerte"|"critique", immediat, code }`
  selon EX-5.12 et EX-8.9 (la gigue est tirée par l'appelant).
  `attenteTransitoire({ httpStatus, retryAfterS, retry, k, premier408 })` est
  la table unique de l'attente de reprise (EX-8.9, révision 0.4), que le
  planificateur appelle aussi : `{ attenteMs, raison: "retry_after"|"immediat"|"backoff" }` ;
  `d = min(retry.max_ms, max(retry.initial_ms, Retry-After))` quand la
  réponse 429 ou 503 en porte un (sans gigue) ; `d = 0` sur le premier 408
  d'une demande chez un prestataire ; sinon
  `min(retry.max_ms, retry.initial_ms × retry.factor^(k−1))`, la gigue
  `[0, retry.jitter_ms]` s'ajoutant au seul `backoff` ; un `Retry-After`
  porté par une réponse 408, 500, 502 ou 504 n'est pas suivi.
  `lireRetryAfter(valeur, maintenantMs)` lit secondes ou date RFC 1123
  (ramenée à un délai depuis la réception) et plafonne à `RETRY_AFTER_MAX_S`
  (604 800, borne de `$defs/tentative`) ; `bornerRetryAfter(s)` plafonne une
  valeur déjà lue : c'est la valeur consignée `retry_after_s`.
- `DepotAncres.ouvrir({ racine, orgId, journalId, signaler })` écrit sous
  `<racine>/<org_id>/<journal_id>/ancres/periode-<period_start sur dix chiffres>/`
  les fichiers d'EX-5.14 (noms exacts, `fsync`, création exclusive : jamais
  de réécriture) : `ecrirePiece(periodStart, "rfc3161"|"ots", nom, octets)`,
  `nomPiece({ objet, imprint, providerId, attemptId })`,
  `ajouterAcquisition(periodStart, enregistrement)` (une ligne JCS intégral
  par tentative), `lireAcquisitions(periodStart) → { enregistrements, tronquee, illisibles: [{ ligne, raison }] }`
  (une ligne illisible est ignorée et signalée par `signaler`, jamais
  réparée ; le réemploi des nonces est contrôlé par un index en mémoire
  construit à la première consultation et tenu à jour par
  `ajouterAcquisition` ; `oublierIndexNonces()` pour un autre processus
  écrivain ; chaque enregistrement rendu est une `copieAutonome` : aucune de
  ses chaînes ne retient le texte du fichier relu, ce qui borne la mémoire
  des valeurs gardées, index des nonces et résumés d'export compris),
  `dernieresAcquisitions(periodStart)` (dernier état de chaque `attempt_id` :
  la T-10 différée ajoute une ligne pour une tentative déjà consignée, avec
  `checks.T-10`, `revoked`, `files.crls`, `revocation`), `periodes()`,
  `nonceConnu(nonce)`, `dejaPromu(objet, imprint, periodStart)`,
  `promu(objet, periodStart, imprint)` (le dernier enregistrement `promoted`
  non révoqué, EX-5.8 ; à défaut `choisirPromu` parmi les `obtenue`).
- `construireFiche(prestataire, { epreuve })` rend le document
  `prestataire-<id>.json` d'EX-10.6 (sans `auth`, `version`,
  `anchor_certificates_sha256`, `anchor_certificates_subjects`, instantané
  `qualified`, `qualified_notice` (mention « non qualifié »),
  `revocation_sources`, `acceptance_test`) ; `verifierFiche(fiche) → { conforme, ecarts }`
  applique AN-54 ; `epreuveAcceptation({ prestataire, transport, horloge, aleatoire, fraicheur, imprint })`
  joue EX-11.4 sans rien écrire.

## B. Client OpenTimestamps (`src/ots/`)

Sections : CT-5 §6 (EX-6.1 à EX-6.10, AN-16 à AN-21), EX-8.11 ; CT-6 §10
(format §10.2, fichier d'en-têtes §10.3 et schéma `entetes-bitcoin-v0`, O-1 à
O-5 et O-7 de §10.4), §13.2, §13.4.

```js
import {
  lireOts, ecrireOts, fusionnerOts, construirePreuve, // CT-6 §10.2 ; EX-6.4 (ordre de sérialisation), EX-6.6 (fusion)
  verifierOts, etatPreuve, hauteursAttestees, admissionApresFusion, // O-1, O-2, O-3, O-7 ; O-4 et O-5 avec des en-têtes (EX-6.9)
  engagement,                                  // EX-6.2 (1) : e = SHA-256(empreinte ‖ nonce 16 octets)
  soumettre,                                   // EX-6.2 (2) à (4) : POST /digest à chaque calendrier
  mettreANiveau, cadenceMiseANiveau, relireReponseCalendrier, // EX-6.6, EX-8.11
  fichierEntetes, lireFichierEntetes, rpcBitcoinHttp, // EX-6.8 : entetes-bitcoin.json depuis bitcoin_rpc ou fichier
  DepotOts,                                    // EX-6.5 : ots/<objet>-<n>.ots, création exclusive, dernière version
  transportHttps,                              // EX-6.2, EX-6.6 : HTTPS, Accept, corps borné à 10 000 octets
} from "@noortrace/ancrage/ots";
```

Contrat :

- `soumettre({ empreinte: hex32, nonce: Uint8Array(16), calendriers: string[], minReponses, delaiMs, transport, horloge })`
  rend `{ engagement, reponses: [{ calendrier, status, octets|null, erreur|null, dureeMs, attestations }], valides, ecrire, octets|null, attestation: "en_attente"|"complete"|"aucune", instant, dureeMs }` ;
  le `data` de l'entrée `reponse_ots` (`request_id`, `calendars_answered` =
  `valides`, `attestation`, `proof_sha256` = SHA-256 des octets, `proof_size`)
  est construit par l'appelant. Le rejeu avec le même nonce rend le même
  engagement (EX-6.2) : le composant garde le nonce dans
  `ots/<objet>.nonce` du répertoire de la période.
- `mettreANiveau({ preuve, listeBlanche, transport, horloge, delaiMs, entetes: document | async ({ hauteurs }) → document|null, reseau })`
  rend `{ nouvelle: octets|null, etat: "complete"|"en_attente", refus: [{ uri, motif, detail }], reponses, hauteurs, verification, instant }` ;
  une preuve fusionnée est vérifiée (O-1, O-3, et O-4, O-5 avec des en-têtes)
  avant d'être rendue ; une URI hors liste blanche est ignorée avec le refus
  `hors_liste_blanche`.
- `transport` est injectable : `{ post(url, octets, entetes, delaiMs, options?) → { status, entetes, corps } ; get(url, entetes, delaiMs, options?) → … }`,
  corps borné à 10 000 octets ; `transportHttps({ fetch, tailleMax })` est
  l'implémentation par défaut (HTTPS, `http://` admis vers une adresse
  locale pour les essais, redirection refusée).
- `verifierOts({ octets, empreinteAttendue, entetes|null, ancre?, reseau? })` rend
  `{ checks: { "O-1"…"O-5", "O-7" }, raisons, details, attestations, etat, empreinte, retenue, avertissements }`.
  `lireOts` et `relireReponseCalendrier` appliquent la lecture stricte de
  CT-6 EX-10.2 et EX-10.5 (révision 0.5) : `varuint` minimaux, profondeur,
  bornes, et **forme canonique d'un nœud** : deux attestations identiques ou
  deux opérations identiques sous un même nœud rendent le fichier
  inexploitable (`ErreurOts`, code `doublon` ; O-1 `echoue`, détail
  « doublon : … » ; vecteur `o1-attestation-en-double.ots`).
- `fichierEntetes({ source: headers_source, hauteurs: [h, h'], rpc | fichier })`
  (asynchrone) rend le document `entetes-bitcoin-v0` d'EX-6.8 ; `rpc` est un
  client `{ appeler(methode, params) }` (`rpcBitcoinHttp({ url, auth, transport })`
  par défaut, `auth` résolu en octets par l'appelant), `fichier` le contenu
  du fichier d'exploitation.
- `DepotOts.ouvrir({ racine, orgId, journalId })` partage la racine et les
  noms d'EX-5.14 avec `DepotAncres` : `ecrire({ periodStart, objet, octets }) → { chemin, nom, version, fichier }`,
  `derniere({ periodStart, objet })`, `versions(...)`, `ecrireEntetes({ periodStart, document })`
  (création exclusive, `fichier_existant` sinon), `lireEntetes(periodStart)`,
  `repertoirePeriode(periodStart)`. `objet` vaut `manifeste` ou
  `point-<checkpointHash sans 0x>`.

## C. Planificateur, file, configuration, échéances, comptages (`src/planificateur/`)

Sections : CT-5 §3.3 et §3.6, §4 (EX-4.1 à EX-4.13, AN-1 à AN-4), §5.3
(EX-5.6 à EX-5.9, AN-12, AN-13), EX-5.11, EX-5.12, EX-6.1, §8 en entier
(EX-8.1 à EX-8.16, AN-32 à AN-43), §9.2 (EX-9.3 à EX-9.7), §10.2 (EX-10.7,
AN-61), §12 (EX-12.1, EX-12.2, AN-59), annexe A.

```js
import {
  validerConfiguration, projection, validerProjection, // AN-1 (schéma ancrage-v0 puis les huit règles d'EX-4.9) ; EX-8.2
  creerPlanificateur, Planificateur, ErreurPlanificateur, // EX-8.13 : machine à états déterministe, horloge injectée, sans réseau
  rejouerTrace, comparerTrace, noncesVecteurs, noncesAleatoires, // EX-8.16, AN-42
  FileDurable, lireFiles, decoderFile, trierDemandes, estFinale, ETATS_FINAUX, idCoherent, ErreurDemandeNonConforme, // EX-8.5, EX-8.2
  dernieresLignes, validerLigneDemande, totalTentatives, supprimerResidusCompactage, // EX-8.5 règles 5 et 7, EX-8.12 (CT-5 révision 0.6)
  FENETRE_TENTATIVES, COMPACT_BYTES_DEFAUT, DELAI_APRES_ECHEC_MS, SUFFIXE_COMPACTAGE, // 32 ; 16 777 216 ; 60 000 ; ".compactage"
  echeances, tableEcheances, constaterCadence, // EX-4.2, EX-4.3, AN-2
  admettrePoint, admettreManifeste, verifierSerie, // AN-3
  pointsAAncrer, compterJetons, cout,          // AN-4, EX-4.6, EX-4.11, EX-12.1, EX-12.2, AN-59
  verifierCompletudeRegistre,                  // EX-10.7, AN-61
  Supervision, METRIQUES_ANCRAGE, EVENEMENTS_JOURNAL, EVENEMENTS_TENTATIVE, MAX_LIGNES_DEFAUT, normaliserValeurEtiquette, // 8.9 : métriques (noms exacts d'EX-8.15) et lignes de journal
  requeteTimeStampReq, relireTimeStampReq,     // EX-5.1 (noms distincts de ceux de src/rfc3161/ à l'agrégation)
  SCHEMA_ANCRAGE, SCHEMA_PLANIFICATEUR, REGISTRE_ANCRAGE, PROFILS,
} from "@noortrace/ancrage/planificateur";
```

Contrat :

- `validerConfiguration(document, { profil, checkpointIntervalEnregistreur })`
  rend `{ valide, erreurs: [{ regle, message }], projection }` (règles `schema`,
  `1` à `8`) ; `projection(document)` est la `$defs/configuration` d'EX-8.2.
  Règle 4 : `http://` est refusé pour tout prestataire autre que le serveur
  interne, dans tout profil, et admis pour le serveur interne vers une
  adresse locale seulement (EX-5.5) ; `auth` `aucune` de même. Le serveur
  interne est le rôle `interne` et, hors production seulement (CT-5
  révision 0.9), le `principal` dont `qualified` vaut `null`
  (`commeServeurInterne(prestataire, production)`, exporté) ; en production,
  ce principal est refusé (`principal … sans qualified`, et `http://` ou
  `auth` `aucune` avec la raison « le serveur RFC 3161 interne n'est admis
  comme principal que hors production »).
- `creerPlanificateur(projection, { maintenant, aleatoire, gigues, nonces, file, fileInitiale, sansRegistre })`
  rend un `Planificateur` : `traiter(entree) → action_attendue[]`, `file() → demande[]`
  (rangées par `created_at` puis `id`), `echeances(periodStart, org_id, journal_id)`,
  `actives()`, `tic()`, `demandes` (Map des demandes courantes). `nonces` =
  `{ rfc3161(p) → bigint, ots(p) → Uint8Array(16), gigue(max) }` (dérivation
  des vecteurs ou tirage ; `noncesAleatoires(aleatoire)` par défaut) ; `file`
  reçoit chaque `demande` écrite (`ecrire(demande)`, avant l'action qui en
  découle, EX-8.5 règle 1) ; `fileInitiale` : demandes relues ;
  `sansRegistre` : aucune ancre au registre (hors production).
  Les dix types d'entrée et les treize actions du schéma sont tous servis ;
  le planificateur **ne fait aucun appel réseau, ne lit aucun fichier, ne
  vérifie aucun jeton**. L'entrée `inclusion_registre` admet un champ
  facultatif `capture_size`.
- Trois entrées hors schéma (règle 1) : `relever(requestId, { t, reason })`
  (EX-5.9 : un `jeton_periode` ouvert part aussi au secours comme sur une
  erreur permanente), `revoquer(requestId, { t, provider })` (EX-5.10
  étape 10, EX-8.3 : `obtenue → a_reprendre`, tentative promue marquée
  `echec_permanente`/`revoque`, alerte `revoque`, relève au secours ou reprise
  au pas `retry.max_ms` ; l'alternance d'EX-8.9 entre prestataires épuisés
  exclut le prestataire révoqué tant qu'un autre candidat existe) et
  `rejeter(requestId, { t, attempt, code = "entree_non_conforme", detail })`
  (un résultat de client que le schéma refuse devient une issue d'échec
  conforme : jeton `echec_permanente` puis conduite d'une erreur permanente,
  OpenTimestamps `echec_transitoire` et soumission rejouée, registre
  `echec_registre` de ce code ; `detail` est le chemin JSON de l'écart) ;
  chacune rend les actions produites. `reconfigurer(projection)` remplace la
  projection (EX-4.9, rechargement). `ErreurPlanificateur` porte `code` et
  `chemin`.
- EX-9.5 : une ancre de point « encore à envoyer » est une demande
  `a_envoyer`, ou `a_reprendre` dont aucune tentative n'a été admise par un
  nœud (`noeud_injoignable`, `transaction_refusee`) ; elle passe `remplacee`
  quand un point plus récent est admis. Une ancre dont une transaction est
  partie (`recu_absent`) suit la reprise de CT-4 §8.6.
- `rejouerTrace(trace)` rend, pour chacune des 24 traces de
  `spec/vecteurs/ct-5/planification/` (CT-5 révision 0.6, dont
  `file-fenetre-32` et `file-fenetre-32-redemarrage`), `expected` et
  `queue_after` à l'identique (AN-42).
- **Révision 0.6 de CT-5 (D2, D3).** Fenêtre de 32 tentatives (EX-8.5,
  règle 7) : chaque ligne écrite porte au plus 32 tentatives rangées par `n`
  croissant (les `en_cours`, puis les plus récentes) et `attempts_total`
  (toujours écrit, 0 sans tentative, plus grand `n`) ; `n` n'est jamais
  renuméroté et une tentative nouvelle a le rang `attempts_total + 1`,
  reprise au démarrage comprise (EX-8.12) ; une demande relue sans
  `attempts_total` (avant 0.6) vaut le nombre de ses tentatives
  (`totalTentatives`), et garde sa forme lue tant qu'elle n'est pas
  réécrite. Une réponse à une tentative sortie de la fenêtre (rang au plus
  `attempts_total`) est conservée (`stocker`, borne calculée avec le nonce
  que la mémoire garde de la tentative, nulle s'il est inconnu) et consignée
  `tentative_close`, non promue. La mémoire du planificateur garde, des
  tentatives sorties, les échecs transitoires consécutifs par prestataire
  (attente d'EX-8.9), le compte des échecs transitoires, l'admission d'une
  transaction par un nœud (EX-9.5) et les nonces ; après un redémarrage,
  les tentatives sorties sont inconnues : une ancre qui en a n'est pas tenue
  pour « encore à envoyer ». Lignes `anchor_retry`, `anchor_fallback`,
  `anchor_response_rejected` : membres `attempt` (rang `n`) et `attempt_id`
  (`<kind>:<16 hex>:<n>`, nul pour un rang qui ne désigne aucune tentative)
  (EX-8.15) ; `tentativeDe(action)` rend la tentative reprise par une action
  `programmer` (la ligne `anchor_retry` du composant). Ligne
  `checkpoint_countersigned` (EX-3.5, 8.9) : `d_admission_s` après
  `d_point_s` ; cinq instants tronqués à la seconde depuis `D_k` (depuis
  `period_end` pour le repli) : `checkpoint_ts`, admission (instant de
  l'entrée `point_produit`, ou de `stockage_relu` pour un point relu ; pour
  une demande relue de la file, son `created_at`), premier envoi, envoi de
  la tentative promue, `genTime + précision` ; chaque composante est la
  différence avec l'instant précédent, `d_attente_s` court donc depuis
  l'admission et la somme vaut `d_jeton_s`.
- Alertes de cadence et du jeton d'un point (EX-4.1, 8.9, AN-2) :
  `point_manquant` (ligne `point_manquant` avec `last_checkpoint_ts`, `gap_s`,
  puis alerte majeure) quand aucun point n'est admis pendant `2 × c_K` après
  le **`checkpoint_ts` déclaré** du dernier point admis, non après son
  admission ni après le démarrage : un point admis longtemps après sa
  production (saut d'horloge, arrêt, reconstruction par `stockage_relu`)
  lève l'alerte dès l'entrée suivante, datée de l'instant où elle était due ;
  une seule alerte par silence, réarmée au point suivant ; le point de
  clôture (`checkpoint_ts ≥ period_end`) et une période close n'arment aucune
  minuterie. À la promotion du jeton d'un point, après la ligne
  `checkpoint_countersigned` et les alertes d'EX-5.11 (`horloge_suspecte`,
  `reponse_tardive_promue`) : `jeton_anterieur_au_point` (majeure) si
  `genTime + précision < checkpoint_ts − clock_tolerance_s`, puis
  `contresignature_tardive` (mineure) si `genTime + précision − checkpoint_ts > c_T`.
- `FileDurable.ouvrir({ repertoire, epoque, fdatasync: true, compactBytes = 16777216, monotone, journal, crochet })` écrit
  `file-<epoch>.ndjson` (JCS intégral d'une `$defs/demande` par ligne) et
  garantit la règle 1 d'EX-8.5 ; à l'ouverture, tout
  `file-<n>.ndjson.compactage` du répertoire est supprimé (EX-8.12 ;
  `residus` : noms supprimés ; seul fichier que le composant supprime,
  EX-8.14). Compactage du fichier courant (EX-8.5, règle 5, révision 0.6) :
  `compacter({ declencheur })` (appelé par le composant à chaque clôture) et
  `declencher()` (après chaque ligne : taille > `compactBytes` et > `2 × S_0`,
  au plus une tentative par minute de `monotone()` après un échec) :
  relecture (règle 3), fichier neuf `.compactage` avec la dernière ligne de
  chaque `id`, octets tels quels, dans l'ordre où elles figurent
  (`dernieresLignes`), `fdatasync`, `rename`, `fsync` du répertoire,
  réouverture du descripteur ; `journal(niveau, evenement, champs)` reçoit
  `anchor_queue_compacted` (`bytes_before`, `bytes_after`, `requests`) ou
  `anchor_queue_compaction_failed` (`step` : `relecture`, `ecriture`,
  `fdatasync`, `renommage`, `repertoire` ; `errno` ; `bytes`), jamais une
  exception ; après un échec aux pas (a) à (d), l'ancien fichier reste en
  place et l'ajout continue sur l'ancien descripteur ; après un échec au pas
  (e), le renommage étant fait, l'ajout continue sur le fichier courant (le
  neuf). Une ligne demandée pendant un compactage est écrite juste après lui
  (`{ differee: true }`). `mesures()` rend `{ taille, taille_max, s0, seuil,
  compact_bytes, compactages, echecs, lignes }` ; `seuil()` vaut
  `max(compactBytes, 2 × S_0)` ; `crochet(pas)` (essais) est appelé avant
  chaque pas. À l'écriture, une ligne de plus de 32 tentatives est refusée
  (`ErreurDemandeNonConforme`) ; à la lecture, `validerLigneDemande` admet une
  ligne sans `attempts_total` de plus de 32 tentatives (avant 0.6). La
  méthode statique `FileDurable.compacter(repertoire, epoque, { courante })`
  reste celle des fichiers d'époques antérieures (`file-<epoch>.<n>.compact.ndjson`) ; une demande que le schéma `$defs/demande`
  refuse lève `ErreurDemandeNonConforme` (`chemin` de l'écart) et n'est pas
  écrite ; `lireFiles(repertoire) → { demandes, parId, tronquees, fichiers }`
  fusionne tous les fichiers `file-*.ndjson` (règle 6 ; lignes tronquées ou
  hostiles signalées, jamais réparées ; une ligne dont
  `id ≠ <kind>:<subject.hash>` est refusée avec la raison `id_incoherent`,
  `idCoherent(demande)`).
- `admettrePoint({ point, serie, cles, hashesPeriode|null, evenements|null, periodStart, org_id, journal_id, firstSeq, lastHashPrecedent })`
  et `admettreManifeste({ manifeste, signature, cles })` rendent
  `{ admis, empreinte, regle|null, detail }` (AN-3 ; règles `format`,
  `period_start`, `signature`, `chainage`, `monotonie`, `racine`, `last_seq`,
  `last_hash`) ; `cles` : `cles.json`, un tableau de clés ou une `Map`.
- `Supervision({ journal, horloge, prestatairesExterieurs, journalAbrege, maxLignes })` :
  `metriques()` (format d'exposition texte, noms exacts d'EX-8.15 ; valeurs
  d'étiquette normalisées par `normaliserValeurEtiquette` : minuscules,
  caractères hors de `[a-z0-9_:.-]` remplacés par `_`),
  `releverActions({ actions, file, maintenant })` (`noortrace_anchoring_d_registre_s`
  observé une fois par ancre, à la passe dont une action `ecrire_file` la fait
  passer à `obtenue`, jamais à chaque relevé de la file : étape 7),
  `consignerActions(actions)`,
  `consigner(niveau, evenement, champs)` par un `journal` injecté
  (`consigner(niveau, composant, evenement, data)`, celui de l'enregistreur,
  CT-2 §17.3) ; les clés qui ressemblent à un jeton, une pièce, un secret ou
  une adresse sont refusées (AN-43) ; les lignes gardées en mémoire sont
  bornées (`maxLignes`, `MAX_LIGNES_DEFAUT` = 10 000, compteur `dropped`) ;
  une métrique en défaut est consignée une fois et ne fait jamais perdre une
  ligne du journal.

## D. Registre : ancre des points et des périodes (`src/registre/`)

Sections : CT-5 §9 (EX-9.1 à EX-9.9, AN-44 à AN-49), EX-8.10, EX-10.4 ; CT-4
§4.5, §6.4 à §6.7, §7.3, §8.2, §8.3, §8.6, §8.7, §9 (CP-1 à CP-6, index
`operations-registre-v0`), §9.6 ; CT-6 §11 ; CT-2 EX-11.19 (clé de chaîne).

```js
import {
  SignataireChaine, SignataireChaineFichier,   // CT-2 EX-11.19 : interface { adresse(), signerCondense(hash32) → { r, s, v } } ; classe D (développement)
  signatureDepuisDer,                          // étape 7 : signature DER d'un service (classe B) → { r, s bas, v recouvré }
  encoderRegisterRecorder, encoderRevokeRecorder, // étape 7 : relais de l'inscription et de la révocation (CT-4 §8.4)
  encoderAnchor, encoderSubmitPeriod, empreinteAncre, periodDigest, anchorDigest, hachageSigne, // CT-4 §6
  construireTransaction, signerTransaction, lireTransaction, verifierRG15, // CT-4 RG-15
  ClientRpc,                                   // JSON-RPC vers un ou plusieurs validateurs (EX-8.15 : mêmes octets à chacun)
  Envoyeur, lireEnvois, envoisSansIssue,       // CT-4 §8.6 : envoi-<hachage>.json, attente du reçu, renvoyer, remplacer, issue
  capturer, verifierCapture, listerCaptures,   // CT-4 §9.4 : CP-1 à CP-6, index de capture
  lookup, recorderOf, recorderByPubKey, isKnown, latestPeriodOf, getPeriod, classerEmpreinte, // CT-4 OP-9, OP-10, OP-12
  entreeRegistre, exporterPartiesRegistre, choisirCaptures, // EX-10.4 ; CT-4 §9.6
  DOC_TYPE_PERIODE, DOC_TYPE_POINT_DE_CONTROLE,
} from "@noortrace/ancrage/registre";
```

Contrat :

- `new Envoyeur({ rpc, repertoireEnvois, instance: { evmChainId, bftChainId, contrats, fees, jeux }, horloge, attendre, delais, journal })`.
  `ancrer({ orgId, journalId, objet, docType, cle, fingerprint?, clePublique?, requestId?, sansInscription? })`
  envoie `anchor` (EX-9.3) et rend `{ type: "inclusion_registre", data: { request_id, block_number, capture_sha256 }, outputs }`
  une fois le reçu obtenu **et la capture écrite** (AN-48), ou
  `{ type: "echec_registre", data: { request_id, code }, outputs }` (codes :
  `empreinte_squattee`, `noeud_injoignable`, `recu_absent`, `attente_nonce`,
  `transaction_refusee`, `transaction_annulee`, `deja_fait`,
  `cle_chaine_non_inscrite`, `refus_<raison>`…). `objet` est le
  `checkpointHash` ou le `periodHash` (l'empreinte est recalculée, AN-44) ;
  `clePublique` (clé Ed25519 du point) sert AN-46 ; `requestId` est celui de
  la file (`LISEZMOI.md`, lecture 1 du registre). Le nonce signé est le plus
  grand `eth_getTransactionCount(expéditeur, "latest")` des points qui
  répondent (CT-4 EX-8.14 ; un validateur en retard d'un bloc ne fait pas
  signer un nonce déjà consommé). L'`Envoyeur` refuse un
  second envoi tant que le premier est sans issue (OP-3, `attente_nonce`,
  `outputs.pending`) ; `renvoyer(transactionHash, { requestId })` et
  `remplacer(transactionHash, { cle, requestId })` appliquent CT-4 EX-8.16.
  Un reçu `0x1` sans le journal attendu ne clôt jamais l'envoi : relu sur
  chaque autre point, puis issue incertaine (`recu_incertain`, aucun fichier
  d'issue) et renvoi jusqu'à la capture ; un `deja_fait` sans capture relit
  la transaction de l'envoi connu et la capture (ligne
  `registry_capture_resumed`). L'`Envoyeur` tient un index en mémoire des
  envois, issues et captures (`envoi(transactionHash)`, `oublierIndex()`
  pour un autre processus écrivain ; `envoisSansIssueParHash`).
  `clore({ periodMeta, signatures, cle, membres?, seuil?, periodePrecedente?, requestId? })`
  fait de même pour `submitPeriod` (CT-4 §8.2 ; `periodMeta` au format
  `meta_periode` de CT-4 : `org_id`, `journal_id`, `period_hash`, `root`,
  `period_start`, `period_end`, `first_seq`, `last_seq`, `version`, `uri`).
  Étape 7 : `inscrire({ demande, cle, requestId? })` et
  `revoquer({ demande, cle, requestId? })` relaient `registerRecorder` et
  `revokeRecorder` (CT-4 §7.7, §8.4) depuis une `demande_signature`
  (`inscription`, `revocation`) avec `cle` comme expéditeur : avant tout
  envoi, opération, `evm_chain_id` et `contract` (= `recorder_registry`) de
  l'instance, OP-6 et OP-7 au seuil (`verifierDemande`), OP-8 (inscription :
  clé de chaîne ni active ni révoquée, `cle_revoquee`, `cle_deja_active`,
  clé Ed25519 active ailleurs `cle_ed25519_active` ; révocation :
  `registeredAt` lu égal à `registered_at`, `cle_inconnue`) ; une opération
  déjà faite à l'identique rend `{ type: "deja_fait" }` sans envoi (ligne
  `registry_already_done`) ; sinon envoi, reçu, capture (rôles
  `inscription`, `revocation` : journaux `RecorderRegistered`,
  `RecorderRevoked`, décodés par `decoderJournal`) et le même résultat
  qu'`ancrer`.
- `capturer({ rpc, transactionHash, role, contrat, horloge, repertoire, instance, attendre, sending, attendu, point, recu })`
  applique CP-1 à CP-6 et écrit `bloc-<h>.json`, `recu-<hash>.json`,
  `certificat-<h>.json`, `capture-<h>-<index>-<rôle>.json` (noms exacts,
  octets des réponses tels que reçus, `fsync`), idempotente (EX-9.3) ; un
  certificat jamais persisté rend `certificat_indisponible` (CP-4) ;
  `verifierCapture` rend CP-2 à CP-6 `echoue` sur un index ou un bloc
  corrompu, jamais une exception.
- `new ClientRpc({ points, transport?, delaiMs?, tailleMax?, identifiants? })`
  (`identifiants` : identifiant de validateur par point, écrit dans
  `node.validator_id` de l'index).
- `SignataireChaineFichier.depuisOctets(source)` lit une clé secp256k1 de 32
  octets (brut, hexadécimal, PKCS#8 PEM ou DER, SEC1 PEM) depuis des octets
  résolus par l'appelant ; classe D, refusée en production par CT-2 ;
  `effacer()` (étape 7) remet la clé à zéro, toute signature est ensuite
  refusée. Les classes B et C sont construites par l'enregistreur
  (`paquets/enregistreur/src/cle-chaine.mjs`) sur cette même interface.
- `signatureDepuisDer(hash32, der, adresse)` (étape 7) : séquence DER de deux
  entiers (forme minimale exigée, aucun octet en trop, `r` et `s` dans
  [1, n − 1]) ramenée à `s` bas, `v` ∈ {27, 28} trouvé en recouvrant
  `adresse` ; sinon une erreur.

## E. Serveur RFC 3161 interne non qualifié (`src/serveur-interne/`, `bin/noortrace-tsa-interne`)

Sections : CT-5 §7 (EX-7.1 à EX-7.4, AN-22 à AN-31), §11.3 ; RFC 3161 §2.4,
RFC 5816 ; CT-6 §9.4, §9.5.

```js
import {
  Autorite,                                    // clé et certificat de l'unité (RSA ≥ 3072 ou ECDSA P-256), politique, précision, compteur
  repondre,                                    // TimeStampReq (octets) → TimeStampResp (octets) : granted, ou rejet
  demarrerServeur,                             // HTTP sur 127.0.0.1 (AN-27), ou TLS avec authentification du client
  initialiserAutorite, chargerAutorite, publierCrl, // AC et unité de développement, CRL publiée (AN-22, AN-31)
  Compteur, CompteurMemoire,                   // numéro de série durable (AN-26)
} from "@noortrace/ancrage/serveur-interne";
```

Contrat :

- `repondre({ requete: Uint8Array, autorite, horloge })` rend
  `{ octets, statut: "granted"|"rejection", serial, echec, raison, jeton, tstInfo, genTime, requete }` :
  `granted` avec `TSTInfo` (`version 1`, politique, `messageImprint` recopié,
  `serialNumber` strictement croissant et durable (AN-26), `genTime` à la
  seconde avec `accuracy` ≤ 1 s (AN-24), `nonce` recopié (AN-25), `tsa`
  `directoryName` du sujet), `SignedData` avec le certificat de l'unité
  (AN-30), `signingCertificateV2` SHA-256, signature
  `sha256WithRSAEncryption` ou `ecdsa-with-SHA256` ; rejets `badAlg` (AN-23),
  `unacceptedPolicy` (AN-29), `badRequest`, `badDataFormat`,
  `timeNotAvailable` (écart d'horloge, `horloge.ecartMs`), `systemFailure`.
- `new Autorite({ clePrivee | signataire, certificat, chaine?, politique, precisionS?, compteur, tsaDansJeton? })`.
- `demarrerServeur({ autorite, ecoute: { hote, port } | { tls: { cle, certificat, acClients, hote?, port } }, journal, horloge, tailleMaxCorps?, chemin? })`
  (asynchrone) rend `{ adresse: { hote, port, url, tls }, fermer(), serveur }` ;
  `POST` avec `Content-Type: application/timestamp-query` seulement ; réponse
  `application/timestamp-reply` ; le serveur n'écrit que son compteur (AN-28
  est satisfaite par `DepotAncres` de `src/rfc3161/`). `Compteur` tient le
  verrou du répertoire sur disque et par chemin dans le processus (un second
  `Compteur` du même processus sur le même répertoire est refusé, AN-26 ;
  `Compteur.ouverts()`, `Compteur.clefRepertoire(repertoire)`).
- `initialiserAutorite({ repertoire, algorithme: "rsa-3072"|"p-256", politique, validiteJours ≤ 1095, crlUrl, horloge, aleatoire, sujetAc?, sujetUnite?, … })`
  écrit les clés (PKCS#8 PEM), les certificats, une CRL vide signée et
  `autorite.json` ; refuse d'écraser ; `publierCrl({ repertoire, horloge, revoques })`
  republie la CRL ; `chargerAutorite({ repertoire, compteur?, inclureAc? })`.
- `GET /sante` rend 200 `ok` sans rien lire de l'autorité ni rien journaliser
  (`CHEMIN_SANTE`) ; toute autre méthode que `POST` reste refusée (405).
- `bin/noortrace-tsa-interne` : `init`, `servir`, `crl`, `ac --repertoire
  <rep> [--crl]` (certificat de l'AC, ou CRL en vigueur, sur la sortie
  standard ; aucune clé privée lue) et `sonde --url
  http://127.0.0.1:<port>/sante` (0 sur 200 `ok` en 2 500 ms au plus, 1
  sinon ; adresse hors de la boucle locale refusée sans connexion) : sonde du
  service `horodatage` de l'installation rapide (CT-8 0.7), image
  `noortrace/tsa-interne`.

## F. Assemblage : composant temps réel (`src/composant.mjs`), outil (`bin/noortrace-ancrage`), intégration à l'enregistreur

### F.1 Composant (`src/composant.mjs`)

```js
import { creerComposantAncrage, ComposantAncrage, ErreurConfigurationAncrage, validerConfigurationComposant, FileTolerante, TIC_MS } from "@noortrace/ancrage";

const composant = creerComposantAncrage({
  configuration,                 // document ancrage-v0 (EX-4.8)
  profil,                        // "developpement" | "test" | "production" (CT-2 §15)
  checkpointIntervalEnregistreur, // checkpoint_interval_s de l'enregistreur, ou null (règle 1 d'EX-4.9)
  contexte, horloge, aleatoire, journal, clients, options,
});
await composant.demarrer();       // lève ErreurConfigurationAncrage si AN-1 ou un secret manque
composant.remettrePoint({ point, checkpointHash, fingerprint, chemin });            // CT-2 rubrique g
composant.remettreCloture({ manifeste, signature, periodHash, fingerprint, periodMeta, cheminManifeste, cheminSignature, cheminSerie });
composant.recharger(configuration);        // → { accepte, erreurs } (EX-4.9 : refusé sans changer l'ancienne)
composant.retirerQualification(providerId); // EX-5.9 ; → actions
composant.metriques();                     // texte au format d'exposition (EX-8.15)
composant.etat();                          // { demarre, arrete, configuration_valide, en_vol, attentes_horloge, demandes, actives, qualifications_retirees, t10_en_attente, clotures_en_attente, ecritures_en_attente, file_en_panne, file_lignes_abandonnees, file: FileDurable.mesures() | null, arret_demande }
composant.demandes();                      // la file, rangée comme queue_after
composant.tic();                           // un tic de l'horloge injectée (tests)
await composant.fiche(providerId, { epreuve }); // → { fiche, verification } (EX-10.6, EX-11.4)
await composant.arreter({ attendre });
```

- **`horloge`** : `{ murale(): ms UTC, monotone(): ms, programmer(delaiMs, fn) → annuler() }`.
  Le composant n'appelle jamais `setTimeout` : `programmer` sert les tics
  (toutes les `options.ticMs`, 1000 ms par défaut, ou plus tôt quand le
  planificateur programme une échéance), et `attendre(ms)` de l'`Envoyeur`.
  L'enregistreur branche son horloge de CT-2 §7.4 (`murale`, `monotone`) et
  `setTimeout`/`clearTimeout` pour `programmer` ; les tests une horloge
  réglable qui déclenche les minuteries échues.
- **`aleatoire(n)`** : `crypto.randomBytes` en exploitation ; sert les nonces
  RFC 3161 (`tirerNonce`, réemploi contrôlé par `acquisitions.ndjson`), les
  nonces OpenTimestamps (durables dans `ots/<objet>.nonce`) et la gigue.
- **`journal`** : `{ consigner(niveau, composant, evenement, data) }`, le
  `JournalExploitation` de l'enregistreur (CT-2 §17.3) ; composant `ancrage`.
- **`contexte`** (tout est résolu par l'appelant, rien n'est lu dans un
  fichier de secrets ni une variable d'environnement) :
  - `org_id`, `journal_id` (hex32), `epoque` (époque du bail, nom du fichier
    de file), `racineStockage` (`storage.root` de CT-2 : les pièces vont sous
    `<racine>/<org_id>/<journal_id>/ancres/periode-<period_start>/`) ;
  - `secrets` : `Map<pointeur JSON, Uint8Array>` des secrets d'`ancrage-v0`
    (`/rfc3161/providers/<i>/auth/secret`, `/opentimestamps/headers_source/auth`) ;
    un pointeur absent refuse la configuration (règle `secrets`) ;
  - `clePublique(keyId) → Uint8Array|null` et, en option, `cles` (`cles.json`
    du journal, tableau de clés ou `Map`) pour AN-3 ;
  - `lireSerie(periodStart) → point[]` (la série écrite par l'enregistreur,
    `points/periode-<period_start>.ndjson` ; le composant ne garde que les
    points qui précèdent celui qu'on lui remet) ;
    `lireHashesPeriode(periodStart) → hex32[]|null` (hash des événements de la
    période dans l'ordre des `seq` : racine et `last_hash` sont alors
    recalculés) ;
  - `listerPeriodes() → [{ manifeste, signature? }]` et `listerPoints() → point[]`
    (manifestes et séries durables, pour `stockage_relu` au démarrage,
    EX-8.12) ;
  - `cleChaine` : `SignataireChaine` (CT-2 EX-11.19), relu à chaque envoi
    (un accesseur est admis : le démon la bascule à la rotation, étape 7) ;
    `cleChainePour(keyId)` (facultatif, étape 7) : la clé de chaîne sous
    laquelle est inscrite la clé Ed25519 qui a signé le point ou le
    manifeste (EX-11.19 point 3 ; à défaut `cleChaine`) ; `clesChaine()`
    (facultatif) : les clés connues, pour retrouver l'expéditeur d'un envoi
    à remplacer au même nonce ; `instance`
    (`{ evmChainId, bftChainId, contrats, fees, jeux }`) quand
    `clients.registre` ne la porte pas ;
  - `signaturesCloture(periodMeta, manifeste) → { signatures, membres, seuil, periodePrecedente }`
    (facultatif) : les signatures des approbateurs au seuil (CT-4 §8.2, pas 4) ;
    sans elle, la clôture `submitPeriod` est laissée à l'outil d'exploitation
    (`period_close_delegated`).
- **`clients`** (facultatifs ; défauts de production entre parenthèses) :
  `rfc3161: { transport }` (`transportHttps()` de `src/rfc3161/`), `ots: { transport }`
  (`transportHttps()` de `src/ots/`), `registre: { envoyeur } | { rpc | points, identifiants, instance, repertoireEnvois, delais }`
  (sans registre : `sansRegistre`, hors production seulement),
  `bitcoinRpc: { appeler }`, `file: { ouvrir, crochet }` (fabrique de `FileDurable`
  et crochet des pas du compactage, tests).
- **Ce que fait le composant** : AN-1 et secrets à la construction
  (`configurationValide()`), refus de démarrer sinon (l'enregistreur
  continue, EX-4.8) ; `FileDurable` sous `queue.path` (époque du contexte ;
  `queue.compact_bytes`, facultative, défaut 16 777 216, lue ici et non par la
  projection, EX-4.8, EX-8.2 ; compactage à chaque clôture après le
  traitement de `periode_close` et sur dépassement de taille, CT-5 révision 0.6),
  relecture de tous les `file-*.ndjson` (`anchor_queue_truncated_line`,
  `file_perdue`), `demarrage` puis `stockage_relu` borné aux périodes closes
  sans leurs trois demandes finales et au dernier point de chaque période
  ouverte (`anchoring_started`, `anchoring_queue_rebuilt`) ; T-10 différées
  reconstruites depuis `acquisitions.ndjson` (`acquisitions_ligne_illisible`
  une fois par fichier illisible par endroits) ; `remettrePoint`/`remettreCloture` : AN-3
  (refus consigné `anchor_admission_refused` et alerté, jamais ancré), puis
  `point_produit`/`periode_close`, la main rendue après l'écriture de la file
  et sans attendre le réseau ; exécution de chaque action dans l'ordre :
  `ecrire_file` (faite par la file avant l'action, AN-32, par
  `FileTolerante` : une écriture impossible pour cause de disque est gardée
  en mémoire dans `max_pending` et rejouée, `anchor_queue_write_failed`,
  `file_perdue`, `anchor_queue_write_recovered` ; une ligne que le schéma
  refuse est consignée `anchor_queue_write_failed` avec
  `reason: demande_non_conforme` et `path`, et abandonnée), `envoyer_rfc3161` → `acquerir`
  puis réinjection de `reponse_rfc3161` (étape 9 impossible : écriture
  rejouée au tic, `anchor_piece_write_failed` ; résultat que le schéma
  refuse : `Planificateur.rejeter`, `entree_non_conforme`), `envoyer_registre` →
  `Envoyeur.ancrer` (puis `renvoyer`/`remplacer` sur `attente_nonce`),
  réinjection d'`inclusion_registre` (avec `capture_size`) ou
  `echec_registre`, et, après l'inclusion de `ancre_registre_periode`,
  `Envoyeur.clore` avec `signaturesCloture` (`period_submitted`,
  `registry_pending` et reprise au tic) ; `soumettre_ots`/`mettre_a_niveau_ots`
  → `src/ots/`, `DepotOts`, nonce durable dans `ots/<objet>.nonce` écrit
  avant toute soumission (tant qu'il ne s'écrit pas, rien n'est soumis et la
  soumission est rejouée au pas de `retry`), `ots_submitted`/`ots_upgraded`,
  réinjection de `reponse_ots`, puis `entetes-bitcoin.json` quand toutes les
  preuves de la période sont complètes (EX-6.8, `bitcoin_headers_written`) ; `programmer` →
  minuterie sur l'horloge injectée ; `stocker`, `alerter`, `journaliser` →
  `Supervision` ; `releve`, `remplacer`, `rejeter_reponse`, `echeance` →
  consignés (`planificateur_<action>`, niveau `debug`) ; `anchor_retry` pour
  chaque reprise programmée d'une demande RFC 3161 ou OpenTimestamps, avec
  `attempt` et `attempt_id` de la tentative reprise (EX-8.15, révision 0.6). T-10
  différée : à `genTime + crl_capture.delay_s`, `capturerCrls` puis
  `verifierRevocation`, `.crl.pem` écrit (toutes les CRL du chemin dans un
  seul fichier PEM), ligne d'acquisition ajoutée (`checks.T-10`, `revoked`,
  `files.crls`, `revocation`), `crl_captured` ; `crl_indisponible` réessayée à
  la cadence de `retry` ; `revoque` → alerte critique et
  `planificateur.revoquer` (relève au secours, EX-8.3). Toute exception d'un
  client est rattrapée, consignée (`anchor_response_rejected`,
  `exception_client`) et transformée en entrée d'échec. `arreter()`
  n'envoie plus rien de nouveau (`anchor_send_deferred` : la ligne `envoyee`
  est écrite, le redémarrage reprend par EX-8.12), attend les actions en vol
  et leurs réponses dans la borne du plus long délai de transport configuré
  plus 5 s (`anchoring_stop_timeout` au-delà), puis traite `arret`
  (`anchoring_stopped`).
- **Lignes du journal propres au composant** (en plus de celles d'EX-8.15,
  consignées depuis les actions) : `config_invalid`, `config_reloaded`,
  `config_reload_rejected`, `anchor_admission_refused`,
  `alerte_admission_refusee`, `alerte_<code>` pour chaque action `alerter`,
  `anchor_queue_write_recovered`, `anchor_piece_write_failed`,
  `acquisitions_ligne_illisible`, `anchor_send_deferred`,
  `anchoring_stop_timeout`, `anchoring_supervision_failed`,
  `provider_qualification_withdrawn`, `period_submitted`,
  `period_close_delegated`, `registry_sent`, `registry_included`,
  `registry_send_failed`, `registry_replaced`, `registry_capture_resumed`,
  `crl_captured`, `crl_indisponible`, `ots_upgrade_refused`,
  `bitcoin_headers_written`, `bitcoin_headers_unavailable`,
  `anchoring_storage_unreadable`, `planificateur_<action>`. Aucune ne porte
  un jeton, une pièce, un secret.

### F.2 Outil `bin/noortrace-ancrage` (`src/cli.mjs`)

Commandes `configuration` (AN-1), `serie` (AN-2, AN-3 sur une série de points
et `acquisitions.ndjson`), `cout` (EX-12.1, EX-12.2, unités symboliques),
`trace` (rejeu d'une trace de 8.10), `fiche` (EX-10.6, `--epreuve` pour
EX-11.4), `acquisitions` (résumé, jeton promu par objet), `completude`
(EX-10.7) ; codes 0 (réussite), 1 (défaut constaté ou erreur), 2 (usage) ;
messages en français ; aucune valeur de secret affichée. `lancer({ argv, horloge, aleatoire, sortie, erreur, env, transport })`
est le point d'entrée injectable.

### F.3 Intégration à l'enregistreur et exportateur

L'exportateur est `src/exportateur.mjs` (export `@noortrace/ancrage/exportateur`,
réuni dans `src/index.mjs`) ; le branchement est
`paquets/enregistreur/src/ancrage-demon.mjs` (rubrique g d'`INTERFACES.md`
de l'enregistreur). Ce que l'enregistreur fournit au composant, exactement :

- **Construction** : `preparerAncrage({ config, secrets, env, horloge, aleatoire, clients })`
  (`cli.mjs`, avant `Coeur.demarrer`) rend `null` quand `anchoring.ancrage`
  est `null`, sinon un `BranchementAncrage` ; il lève
  `ErreurBranchementAncrage` (`raison: classe_cle_chaine`) pour une clé de
  chaîne de classe A, ou `cle_chaine` pour une clé de classe B, C ou D
  illisible ou d'une autre adresse, et le démon refuse de démarrer (code 2). Tout
  autre défaut est porté par l'objet (`etat().raison`) : le démon démarre,
  `anchoring_not_started` est consigné (`document_illisible`,
  `secret_non_resolu`, `instance_registre_absente`, `rpc_url_absente`,
  `configuration_invalide` avec les règles d'AN-1, `demarrage_impossible`) et
  chaque remise donne `anchor_pending`.
- **`configuration`** : le document `ancrage-v0` lu en JSON strict
  (`analyserJsonIntegral`, 1 Mio au plus) au chemin `anchoring.ancrage`.
  **`profil`** : `production` si `recorder.environment` l'est, `developpement`
  sinon. **`checkpointIntervalEnregistreur`** : `checkpoint_interval_s` (60
  par défaut).
- **`contexte.secrets`** : `Map` des pointeurs `/rfc3161/providers/<i>/auth/secret`
  (quand `auth.method ≠ aucune`) et `/opentimestamps/headers_source/auth`
  (quand il n'est pas `null`), résolus par `resoudreSecret` de l'enregistreur
  (`env`, `file`, `vault` par `lireSecretsVault`) ; une référence qui ne se
  résout pas donne `secret_non_resolu` avec le pointeur, jamais la valeur.
- **`contexte.org_id`, `journal_id`** : `recorder.org_id`, `recorder.journal_id` ;
  **`epoque`** : époque du bail de l'écrivain ; **`racineStockage`** :
  `storage.root` (les dépôts d'EX-5.14 écrivent sous
  `<racine>/<org sans 0x>/<journal sans 0x>/ancres/`, lecture F2-1).
- **`contexte.clePublique(keyId)`** : `signataire.clePublique` du cœur pour la
  clé courante, les clés de la chaîne relues dans les segments (événements
  `rotation`) pour les autres.
- **`contexte.lireSerie(P)`** : les points de `points/periode-<P>.ndjson`
  (lecture seule, lignes JCS intégral) ; **`lireHashesPeriode(P)`** : les
  `hash` des événements de la période dans l'ordre des `seq`, relus dans les
  segments ; **`listerPeriodes()`** : `{ manifeste, signature }` de chaque
  `manifestes/periode-*.json` et `.sig` ; **`listerPoints()`** : toutes les
  séries.
- **`contexte.cleChaine`** : signataire construit depuis
  `anchoring.registry.chain_key` selon sa classe (B : AWS KMS
  `ECC_SECG_P256K1` ; C : enveloppe AWS KMS déchiffrée en mémoire ; D :
  `SignataireChaineFichier` ; étape 7, `INTERFACES.md` de l'enregistreur),
  adresse confrontée à `chain_key.address` ; `null` sans registre ;
  accesseur relu à chaque envoi ; **`contexte.cleChainePour(keyId)`** et
  **`contexte.clesChaine()`** après une rotation (étape 7). **`contexte.instance`** :
  `instanceDepuisManifeste` du fichier `instance-registre.json` lu à côté du
  document `ancrage-v0` (lecture F2-4).
- **`contexte.signaturesCloture(periodMeta)`** : rend
  `{ signatures, membres: null, seuil, periodePrecedente: null }` depuis la
  demande signée `demande-cloture-<period_hash>.json` déposée par
  l'exploitant sous `<journal>/registre/` (forme `demande_signature`,
  `operation: cloture`, `verifierDemande` complet), ou **`null`** quand elle
  n'y est pas encore : le composant consigne alors `period_close_delegated`
  (`reason: signatures_en_attente`) et revient au tic suivant, sans alerte
  (lecture F2-3). Une demande d'une autre période ou invalide est consignée
  `period_close_request_refused` et vaut `null`.
- **`horloge`** : l'horloge de l'enregistreur (`murale`, `monotone`),
  `programmer` par `setTimeout`/`clearTimeout` du démon, ou par la minuterie
  de l'horloge que `principal(argv, { horloge })` reçoit (essais). **`aleatoire`** :
  `crypto.randomBytes`. **`journal`** : le `JournalExploitation` du cœur
  (composant `ancrage`). **Métriques** : `composant.metriques()` est
  concaténé aux métriques du cœur sur `/metrics` de la supervision.
- **`clients`** : par défaut `registre: { points: [rpc_url], identifiants: { <url>: v1 }, instance, repertoireEnvois: <journal>/registre }` ;
  les essais injectent `rfc3161.transport`, `ots.transport` et un
  `registre` factice.
- **Cycle** : `Coeur.demarrer({ ancrage })` ; `lier(coeur)` après le
  démarrage de l'écrivain (`anchoring_attached`) ; `remettrePoint`,
  `remettreCloture` par `Ecrivain` (EX-12.27) ; `recharger()` à
  `noortrace-ctl reload` (après la politique ; un document invalide est
  consigné `config_reload_rejected`, l'ancien reste) ; `arreter()` après
  `ecrivain.fermer()` ; `noortrace-ctl ancrage etat|metriques|retirer-qualification <id>`
  par le canal de `ctl-demon.mjs` (SIGURG et fichier de demande).

**Exportateur** (`src/exportateur.mjs`, EX-10.1 à EX-10.5, AN-50 à AN-53) :

```js
choisirPointCouvrant({ serie, leafIndex, acquisitions, preuves, captures })   // → { point, checkpointHash, rang, index, ancres } | null
construirePartiePointsDeControle({ point, hashes, jeton, preuve, capture })  // → { partie, octets, checkpointHash }
piecesPeriode({ depots, periodStart })                                       // jeton promu et preuve du manifeste, en-têtes
partiesRegistre({ repertoireCaptures, periodHash, fingerprint, inscriptions, empreintePoint, jeux, source })
exporterDossier({ event, org_id, journal_id, partiesBase, raisonsBase, leafIndex, hashes, manifeste, periodHash, serie,
                  racineStockage, registre, destination, generated_at, ecrire })
                                                                             // → { dossier, octetsIndex, fichiers, point, pieces, raisons, defauts, resume }
etatAncresPeriode({ racineStockage, orgId, journalId, periodStart, serie, repertoireCaptures, periodHash })
reexportsDus({ dossiersProduits, etatAncres })                               // → [{ seq, hash, period_start, destination, generated_at, raisons }]
controlerAncresDossier({ repertoireDossier, racineStockage, orgId, journalId, periodStart })
RANGS, RAISONS, BORNES_EXPORTATEUR, octetsJsonDossier, nomObjetPoint, derniersEtats, jetonPromuDuPoint, referenceRegistre, depotsJournal, piecesObjet, indexAncresPoints, decoderAncreEmbarquee
```

L'enregistreur (`dossier.mjs`) assemble la base (`assemblerBase` : sept
parties de CT-1, hashes, indice de feuille, série, manifeste) et la passe à
`BranchementAncrage.exporterDossier(base, { destination, generated_at })`
quand le composant est démarré ; sans ancrage, l'export de CT-1 §11 reste
celui du cœur. `generated_at` vient de l'horloge du cœur ; l'exportateur
n'en lit aucune. Les parties sont écrites octet pour octet, `dossier.json`
par `indexerDossier` du noyau, `entetes-bitcoin.json` à côté sans entrée
(CT-6 §4.3). Les essais le confrontent aux dossiers des vecteurs CT-6 et CT-1
(partie `points-de-controle.json` et dossier complet octet pour octet) et au
vérificateur JavaScript et au binaire Go sur les dossiers d'un démon réel.
`resume` est une `copieAutonome` (aucune chaîne ne retient un texte de
fichier relu) : l'appelant peut le garder pour `reexportsDus` sans garder
avec lui `acquisitions.ndjson`. Le branchement de l'enregistreur garde le
résumé le plus récent (par `generated_at`) de chaque événement, clé
`<hash>:<seq>` ; `reexportsDus` ne compte de toute façon que celui-là.

Ce que le paquet ne couvre pas est nommé dans `LISEZMOI.md`, section
« Restes » : clé de chaîne de classe A à C, rotation d'urgence au registre,
commande `exporter` d'un outil hors démon, régénération des vecteurs CT-9,
alertes laissées à CT-8.
