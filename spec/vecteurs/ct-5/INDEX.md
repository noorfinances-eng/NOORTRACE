# Vecteurs CT-5 — ancrage

Produit par `scripts/vecteurs/generer-ct5.mjs` (`npm run vecteurs:ct5`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-5-ancrage.md`](../../CT-5-ancrage.md), annexe A.

Le générateur rejoue tout à l'identique (EX-A.1) ; il lit sans les réécrire l'exemple de référence de CT-1, les manifestes de `spec/vecteurs/ct-1`, les clés de l'autorité de test de CT-6 et deux preuves de `spec/vecteurs/ct-6/ots/preuves` (EX-A.2), et ne touche jamais à `verificateur-independant/` ni à `confrontation/`. Toutes les valeurs de `cout/` sont des unités symboliques, jamais un prix (AN-60) ; aucune adresse, aucun secret, aucun identifiant de compte ne figure dans ces vecteurs (AN-43).

## Rejouer

```bash
npm run vecteurs:ct5                                   # régénère spec/vecteurs/ct-5 (mêmes octets)
node -e 'import("./scripts/lib/ancrage.mjs").then(A => console.log(A.verifierTrace(JSON.parse(require("fs").readFileSync("spec/vecteurs/ct-5/planification/heure-nominale-reference.json","utf8")))))'
cd spec/vecteurs/ct-5/verificateur-independant && go run . ..   # vérificateur Go indépendant (A.5)
```

## constantes.json (A.2)

| Grandeur | Valeur |
|---|---|
| Journal de référence | `org_id` `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab`, `journal_id` `0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b` (`journal-principal`) |
| Période 1 | `[1793710800, 1793714400)`, `periodHash` `0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1`, `generated_at` 2026-11-03T14:00:00.250Z, empreinte d'ancre `0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b` |
| Période 2 | `[1793714400, 1793718000)`, `periodHash` `0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b`, `generated_at` 2026-11-03T15:00:00.112Z, empreinte d'ancre `0x42a549914a125a1a638c3d52feee09856ec93ea103d47fb3890aaa33e979877b` |
| Point K1 | `checkpointHash` `0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4`, `tree_size` 2, `checkpoint_ts` 2026-11-03T13:42:00.000Z, empreinte d'ancre `0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540` |
| Point K2 | `checkpointHash` `0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff`, `tree_size` 4, `checkpoint_ts` 2026-11-03T13:53:00.000Z, empreinte d'ancre `0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44` |
| Point K3 | `checkpointHash` `0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867`, `tree_size` 4, `checkpoint_ts` 2026-11-03T13:54:00.000Z, empreinte d'ancre `0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837` |
| Point K4 | `checkpointHash` `0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107`, `tree_size` 5, `checkpoint_ts` 2026-11-03T14:00:00.250Z, empreinte d'ancre `0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792` |
| Point K5 | `checkpointHash` `0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153`, `tree_size` 0, `checkpoint_ts` 2026-11-03T14:01:00.000Z, empreinte d'ancre `0xe2a9b1f020f6c1d383e63014cfc0d62e7481d27c0136a8ecf81c3170d8c0c020` |
| Point K6 | `checkpointHash` `0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d`, `tree_size` 0, `checkpoint_ts` 2026-11-03T15:00:00.112Z, empreinte d'ancre `0xcb5172d1cce457c9a255d44f26485198462072f98f3aba26a4f7fae9cc601a0d` |
| Journal des vecteurs | `journal-sinistres`, `periodHash` `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914`, `0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19`, `0x5852e3c7f403875b9b634f5e5d7074ea197fc34ecf80e092b9686d8c2dc80594` |
| `docType` | période `0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee`, point `0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178` |
| Nonce RFC 3161 | noortrace/vecteurs/v0/ct-5/nonce-tsa/<journal>/<periode|point>/<empreinte hex sans 0x>/<n> : 64 premiers bits de SHA-256(UTF-8(étiquette)), entier non signé, n ≥ 1 le rang de la tentative ; CT-1 §13 : `noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple` → `0x74a6f4979421411e` |
| Nonce OpenTimestamps | noortrace/vecteurs/v0/ct-5/ots/nonce/<journal>/<periode|point>/<empreinte hex sans 0x> : 16 premiers octets de SHA-256(UTF-8(étiquette)) ; `point-k2-en-attente.ots` : nonce `0x67408294dbd584a4dda160e16129c6b5`, engagement `0xc1cb7611d9e35803bceab098d24a183876e134fcda969d249a92bf5013eca0aa` ; `point-k2-minimal.ots` : `0xa10f0dccae630a2791dde3924b507379` |
| Opérations de calendrier | noortrace/vecteurs/v0/ct-5/ots/calendrier/<alice|bob>/<journal>/<periode|point>/<empreinte hex sans 0x> : 16 premiers octets, argument de f1, puis 08, puis l'attestation en attente de l'URI ; alice `0x86b4b0a3caa98d05a58a4023cc6c953b`, bob `0xda4ee3a72268b161c2f158aec8af42fd` |
| Calendriers | `https://alice.btc.calendar.opentimestamps.org`, `https://bob.btc.calendar.opentimestamps.org` |
| `attempt_id` | `<kind>:<16 premiers hex de l'empreinte>:<n>` |
| Prestataires des traces | `qtsa-principal` (principal, qualified true) ; `qtsa-secours` (secours, qualified true) ; `tsa-interne` (interne, qualified false, politique 1.3.6.1.4.1.99999.1.1) ; `tsa-second-rang` (second_rang, qualified false) |
| Formes représentées | jeton SHA-256(UTF-8("jeton <nom>")), capture SHA-256(UTF-8("capture <request_id> <bloc>")) (4096 octets), preuve SHA-256(UTF-8("preuve <nom>")) |
| Autorité de test | ../ct-6/rfc3161/cles/ac-test.pem, ../ct-6/rfc3161/cles/tsa-test.pem, politique `1.3.6.1.4.1.99999.1.1`, RSA 3072, précision 1 s |
| Unités symboliques | p_q = 1, p_s = 0.2, F = 10000, Q = 10000 : unités, jamais un prix |

## requetes/ (EX-5.1, AN-5, AN-6)

`requetes.json` (`#/$defs/fichier_vecteurs`) : chaque requête `TimeStampReq`, son fichier `.tsq`, octets exacts ; `refusees.json` : constructions que la référence refuse.

| Cas | Empreinte | Politique | Nonce | Taille | SHA-256 | Fichier |
|---|---|---|---|---|---|---|
| `requete-point-k2` | `0x6a8e035a…` | — | `0x74a6f4979421411e` | 69 | `0xe0b39a0b23569bd3fe112fd45811fea46585c7bb7ceda295f57617e405a4ff40` | `requete-point-k2.tsq` |
| `point-k2-exemple` | `0x6a8e035a…` | — | `0x018032ff0d74cfda` | 69 | `0x6f69038e3ba10962a7b6af72d5366e4b04946a9cf06aa2bb17d818bbc6ef736a` | `point-k2-exemple.tsq` |
| `point-k2-exemple-politique-interne` | `0x6a8e035a…` | 1.3.6.1.4.1.99999.1.1 | `0x018032ff0d74cfda` | 81 | `0x5a0dc94d0164a9a084c7114174908dc7a3b757ee1cbb12ceeb212b6c1386c4b8` | `point-k2-exemple-politique-interne.tsq` |
| `periode-1-reference` | `0xa864281e…` | — | `0xf144cca6ec50dcdb` | 70 | `0xd8fc9ff1a6908df641f9bd6e6a6c72e90eacda3837e6b8cc78d82d9f92919399` | `periode-1-reference.tsq` |
| `periode-1-reference-tentative-2` | `0xa864281e…` | — | `0xe514f7e31f6ba99e` | 70 | `0xef6b5679e25d26b16320e1f5ee8339284683f4e70704e11431f2afa325f1f924` | `periode-1-reference-tentative-2.tsq` |
| `periode-1-vecteurs` | `0xae22426f…` | — | `0x29ccc3c9db80e87b` | 69 | `0xdc30519d2596c2df5a87c7f0b6ddde6b1dea95d42737424200532c73be747fd9` | `periode-1-vecteurs.tsq` |

- `requete-point-k2` : La requête d'EX-5.1 : checkpointHash du point K2 de CT-1 §10.5, nonce de CT-1 §13 (0x74a6f4979421411e), à laquelle le jeton de CT-1 §11.2 répond.
- `point-k2-exemple` : Point K2 de l'exemple de référence de CT-1 (checkpointHash), première tentative, sans politique.
- `point-k2-exemple-politique-interne` : Même empreinte, politique du serveur interne de test 1.3.6.1.4.1.99999.1.1.
- `periode-1-reference` : periodHash de la période 1 de l'exemple de référence de CT-1, première tentative (nonce à bit haut : 70 octets).
- `periode-1-reference-tentative-2` : Même empreinte, deuxième tentative : nonce frais.
- `periode-1-vecteurs` : periodHash de la période 1 des vecteurs CT-1 (journal-sinistres), première tentative.

Refusées :

- `condense-31-octets` (AN-5) : Empreinte de 31 octets : messageImprint SHA-256 exige 32 octets (EX-5.1, EX-5.2).
- `nonce-nul` (AN-6) : Nonce 0 : l'entier est dans [1, 2^64 − 1] (EX-5.3).
- `nonce-hors-64-bits` (AN-6) : Nonce 2^64 : hors de [1, 2^64 − 1] (EX-5.3).
- `certreq-faux` (AN-5) : certReq FALSE : certReq vaut toujours TRUE (EX-5.4).
- `nonce-zero-superflu` (AN-5) : Requête point-k2-exemple dont le nonce est encodé 02 09 00 01 80 32 ff 0d 74 cf da (zéro de tête superflu) : la relecture la refuse, l'encodage DER est minimal (EX-5.1).

## reponses/ (EX-5.10 à EX-5.12, AN-8 à AN-11)

`reponses.json` : chaque réponse (fichier `.tsr`, ou réponse HTTP représentée), la requête à laquelle elle répond, les instants d'envoi et de réception, et l'attendu du classement (issue d'EX-5.13, code d'EX-5.10, classe, avertissements, attente de reprise d'EX-8.9). Le jeton extrait est écrit en `.der`. `openssl_verify` : attendu de `openssl ts -verify -queryfile` (confrontation/).

| Cas | Requête | Réponse | Issue | Code | Classe | Avertissements | Reprise | openssl |
|---|---|---|---|---|---|---|---|---|
| `granted-requete-point-k2` | `requete-point-k2.tsq` | `granted-requete-point-k2.tsr` | obtenue | — | — | — | — | OK |
| `granted-point-k2-exemple` | `point-k2-exemple.tsq` | `granted-point-k2-exemple.tsr` | obtenue | — | — | — | — | OK |
| `granted-point-k2-exemple-politique-interne` | `point-k2-exemple-politique-interne.tsq` | `granted-point-k2-exemple-politique-interne.tsr` | obtenue | — | — | — | — | OK |
| `granted-periode-1-reference` | `periode-1-reference.tsq` | `granted-periode-1-reference.tsr` | obtenue | — | — | — | — | OK |
| `granted-periode-1-reference-tentative-2` | `periode-1-reference-tentative-2.tsq` | `granted-periode-1-reference-tentative-2.tsr` | obtenue | — | — | — | — | OK |
| `granted-periode-1-vecteurs` | `periode-1-vecteurs.tsq` | `granted-periode-1-vecteurs.tsr` | obtenue | — | — | — | — | OK |
| `granted-nonce-different` | `point-k2-exemple.tsq` | `granted-nonce-different.tsr` | echec_permanente | nonce_different | permanente | — | — | nonce mismatch |
| `granted-sans-nonce` | `point-k2-exemple.tsq` | `granted-sans-nonce.tsr` | echec_permanente | nonce_absent | permanente | — | — | — |
| `granted-autre-empreinte` | `point-k2-exemple.tsq` | `granted-autre-empreinte.tsr` | echec_permanente | empreinte_differente | permanente | — | — | — |
| `granted-politique-hors-liste` | `point-k2-exemple.tsq` | `granted-politique-hors-liste.tsr` | echec_permanente | politique_refusee | permanente | — | — | — |
| `granted-politique-differente` | `point-k2-exemple-politique-interne.tsq` | `granted-politique-differente.tsr` | echec_permanente | politique_differente | permanente | — | — | — |
| `rejet-unacceptedPolicy` | `point-k2-exemple-politique-interne.tsq` | `rejet-unacceptedPolicy.tsr` | echec_permanente | echec_unacceptedPolicy | permanente | — | — | — |
| `rejet-badAlg` | `point-k2-exemple.tsq` | `rejet-badAlg.tsr` | echec_permanente | echec_badAlg | permanente | — | — | — |
| `rejet-timeNotAvailable` | `point-k2-exemple.tsq` | `rejet-timeNotAvailable.tsr` | echec_transitoire | echec_timeNotAvailable | transitoire | — | 5000 ms (backoff) | — |
| `waiting` | `point-k2-exemple.tsq` | `waiting.tsr` | echec_transitoire | statut_3 | transitoire | — | 5000 ms (backoff) | — |
| `statut-5` | `point-k2-exemple.tsq` | `statut-5.tsr` | echec_permanente | statut_5 | permanente | — | — | — |
| `t6-signature` | `point-k2-exemple.tsq` | `t6-signature.tsr` | echec_permanente | verification_T-6 | permanente | — | — | — |
| `http-503-retry-after-30` | `point-k2-exemple.tsq` | HTTP 503 | echec_transitoire | http_503 | transitoire | — | 30000 ms (retry_after) | — |
| `http-429` | `point-k2-exemple.tsq` | HTTP 429 | echec_transitoire | http_429 | transitoire | — | 5000 ms (backoff) | — |
| `http-408` | `point-k2-exemple.tsq` | HTTP 408 | echec_transitoire | http_408 | transitoire | — | 0 ms (immediat) | — |
| `http-404` | `point-k2-exemple.tsq` | HTTP 404 | echec_permanente | http_404 | permanente | — | — | — |
| `http-401` | `point-k2-exemple.tsq` | HTTP 401 | echec_permanente | http_401 | permanente | — | — | — |
| `type-contenu` | `point-k2-exemple.tsq` | HTTP 200 (text/html) | echec_permanente | type_contenu | permanente | — | — | — |
| `corps-trop-long` | `point-k2-exemple.tsq` | HTTP 200 (131073 octets) | echec_permanente | taille | permanente | — | — | — |
| `reponse-tardive-1` | `point-k2-exemple.tsq` | `reponse-tardive-1.tsr` | reponse_tardive | reponse_tardive | transitoire | — | 5000 ms (backoff) | OK |
| `reponse-tardive-2` | `point-k2-exemple.tsq` | `reponse-tardive-2.tsr` | reponse_tardive | reponse_tardive | transitoire | — | 10000 ms (backoff) | OK |
| `reponse-tardive-3` | `point-k2-exemple.tsq` | `reponse-tardive-3.tsr` | obtenue | — | — | reponse_tardive | — | OK |
| `horloge-suspecte` | `point-k2-exemple.tsq` | `horloge-suspecte.tsr` | obtenue | — | — | horloge_suspecte | — | OK |

- `granted-requete-point-k2` : Le jeton de CT-1 §11.2 lui-même (genTime 2026-11-03T13:53:02Z, numéro de série 1001, nonce de CT-1 §13), reconstruit à l'identique par l'autorité de test : réponse granted.
- `granted-point-k2-exemple` : granted de l'autorité de test à la requête point-k2-exemple (sans politique demandée ; la politique de l'autorité est admise).
- `granted-point-k2-exemple-politique-interne` : granted à la requête qui demande la politique 1.3.6.1.4.1.99999.1.1 : le jeton porte la même politique.
- `granted-periode-1-reference` : granted sur le periodHash de la période 1 de référence (genTime 14:00:05).
- `granted-periode-1-reference-tentative-2` : granted à la deuxième tentative (nonce frais).
- `granted-periode-1-vecteurs` : granted sur le periodHash de la période 1 des vecteurs CT-1 (genTime 2026-11-05T10:00:05Z).
- `granted-nonce-different` : granted dont le nonce du TSTInfo diffère de celui de la requête (nonce + 1) : étape 4, erreur permanente nonce_different, alerte, relève (EX-5.10) ; openssl ts -verify -queryfile répond « nonce mismatch ».
- `granted-sans-nonce` : granted sans nonce dans le TSTInfo : nonce_absent, permanente (EX-5.10, étape 4).
- `granted-autre-empreinte` : granted sur une autre empreinte (le periodHash de la période 1 de référence) : empreinte_differente, permanente (EX-5.10, étape 3).
- `granted-politique-hors-liste` : granted sous la politique 1.3.6.1.4.1.99999.1.2, hors accepted_policies du prestataire : politique_refusee, permanente (EX-5.10, étape 5).
- `granted-politique-differente` : La requête demandait 1.3.6.1.4.1.99999.1.1, le jeton porte 1.3.6.1.4.1.99999.1.2 : politique_differente, permanente (EX-5.4, EX-5.10 étape 5).
- `rejet-unacceptedPolicy` : PKIStatus 2 (rejection), PKIFailureInfo unacceptedPolicy, statusString d'openssl ts, 50 octets : echec_unacceptedPolicy, permanente, la requête est en cause (EX-5.12).
- `rejet-badAlg` : PKIStatus 2, PKIFailureInfo badAlg : echec_badAlg, permanente (EX-5.12).
- `rejet-timeNotAvailable` : PKIStatus 2, PKIFailureInfo timeNotAvailable : echec_timeNotAvailable, transitoire, rejouée avec un nouveau nonce (EX-5.12).
- `waiting` : PKIStatus 3 (waiting), sans jeton : statut_3, transitoire (EX-5.12).
- `statut-5` : PKIStatus 5 (revocationNotification) : statut_5, permanente, alerte critique, relève immédiate (EX-5.12).
- `t6-signature` : granted dont le dernier octet de la signature est inversé : T-6 échoue à l'acquisition, verification_T-6, permanente, le jeton est conservé comme pièce (EX-5.10, étape 6).
- `http-503-retry-after-30` : Réponse HTTP 503 avec Retry-After: 30 (représentée, sans corps) : http_503, transitoire, reprise à 30 s (EX-5.12, EX-8.9).
- `http-429` : HTTP 429 sans Retry-After : http_429, transitoire, attente de retry (5 s à la première reprise, gigue nulle ici).
- `http-408` : HTTP 408 : http_408, transitoire, rejouée immédiatement une fois (EX-8.9).
- `http-404` : HTTP 404 : http_404, permanente, jamais rejouée sans modification (EX-5.12).
- `http-401` : HTTP 401 : http_401, permanente, alerte (secret d'accès en cause, section 13).
- `type-contenu` : HTTP 200 de Content-Type text/html : type_contenu, permanente (EX-5.5).
- `corps-trop-long` : HTTP 200 dont le corps fait 131 073 octets (représenté) : taille, permanente, sans lecture (EX-5.5, EX-5.12).
- `reponse-tardive-1` : granted valable reçu 63 s après l'envoi (max_response_delay_s 60) : reponse_tardive, le jeton est conservé sans être promu, nouvelle tentative avec un nouveau nonce (EX-5.11).
- `reponse-tardive-2` : Deuxième réponse tardive consécutive : encore reponse_tardive (attente de reprise 10 s).
- `reponse-tardive-3` : Troisième réponse tardive consécutive : promue avec l'avertissement reponse_tardive, pour ne pas priver la période d'ancre (EX-5.11).
- `horloge-suspecte` : granted dont le genTime (13:53:02) s'écarte de 182 s de l'instant d'envoi (13:50:00), au-delà de clock_tolerance_s (120) : promu, marqué horloge_suspecte (EX-5.11).

## ots/ (EX-6.4 à EX-6.7, AN-17 à AN-19)

`ots.json` décrit chaque preuve (empreinte, nonce, engagement, branches) ; `mise-a-niveau.json` la paire avant/après de l'EX-6.6 sur les preuves de CT-6.

| Preuve | Empreinte | Taille | SHA-256 | Attendu |
|---|---|---|---|---|
| `point-k2-minimal.ots` | `0x6a8e035a…` | 195 | `0x64a62afc6526fdd0ea34c57ea70eb8e4711f2fc49ff8fc6a3c4cd38596efa8b6` | O-1 à O-3 réussies, O-7 non exécutée (partie_absente), en attente |
| `point-k2-en-attente.ots` | `0x6a8e035a…` | 233 | `0x8bdf7ed01c73e1b53cb1765e7c456c0ca92056af9685bc3c537a06f51182687a` | O-1 à O-3 réussies, O-7 non exécutée (partie_absente), en attente |
| `periode-1-en-attente.ots` | `0xa864281e…` | 233 | `0x4653728041b350ade24761a7dddab80e14e2268c67503c11b2b4eb8489d9bfc8` | O-1 à O-3 réussies, O-7 non exécutée (partie_absente), en attente |
| `mise-a-niveau.json` | période 1 des vecteurs CT-1 | 210 → 316 | `0xf70b77c15a5226d537f34d7288a5b296cad3c0dbd5b0d2fc79d679e5dc3cff1f` | en_attente → complete, fusion égale à `periode-1.ots` |

- `point-k2-minimal.ots` : L'exemple d'EX-6.4 : checkpointHash K2, nonce dérivé de l'étiquette …/ots/nonce/point-k2, deux attestations en attente nues sous l'engagement, triées par URI (alice avant bob) ; 195 octets.
- `point-k2-en-attente.ots` : Preuve en attente à deux calendriers sur checkpointHash K2 : nonce dérivé de …/ots/nonce/journal-principal/point/<K2>, puis une branche par calendrier (opération f1 d'un argument de 16 octets dérivé de …/ots/calendrier/<alice|bob>/<sujet>, 08, attestation en attente de l'URI) ; 233 octets.
- `periode-1-en-attente.ots` : Même construction sur le periodHash de la période 1 de référence (étiquettes …/periode/<periodHash>).
- `mise-a-niveau.json` : Mise à niveau d'EX-6.6 sur les preuves de CT-6 (lues, non copiées) : la preuve en attente o7-en-attente.ots (attestation en attente du calendrier alice au bout des opérations d'agrégation) reçoit du calendrier, pour son engagement, le Timestamp `response` (opérations Bitcoin imitées puis attestation Bitcoin à la hauteur 1001) ; l'attestation en attente est remplacée par ce chemin et la preuve resérialisée est, octet pour octet, periode-1.ots (EX-6.7 : complete).

## planification/ (§8.10, AN-32 à AN-42)

Chaque trace est conforme à la racine de `planificateur-ancrage-v0.schema.json` ; `rejouerTrace` de `scripts/lib/ancrage.mjs` rend `expected` et `queue_after` à l'identique (formes canoniques JCS v0, dans l'ordre). La trace de référence est, forme canonique pour forme canonique, l'exemple de CT-5 §8.10.

| Trace | Entrées | Actions | File au départ | File à l'arrêt | Règles exercées |
|---|---|---|---|---|---|
| `heure-nominale-reference.json` | 19 | 88 | 0 | 9 | EX-4.2, EX-4.3, EX-4.6, EX-4.7, EX-6.2, EX-8.4, EX-8.5 |
| `principal-injoignable.json` | 12 | 57 | 0 | 3 | EX-5.7, EX-5.8, EX-5.12, EX-8.6, EX-8.8, EX-8.9 (AN-37, AN-38) |
| `refus-permanent-releve.json` | 16 | 90 | 0 | 7 | EX-4.4, EX-5.7, EX-5.12, EX-8.3, EX-8.8 |
| `reponse-tardive.json` | 21 | 63 | 0 | 3 | EX-4.3 (sans_objet), EX-4.6, EX-5.11, EX-8.9 |
| `horloge-suspecte.json` | 15 | 74 | 0 | 7 | EX-5.11 (horloge_suspecte), EX-4.3 |
| `echeance-remplacee.json` | 22 | 111 | 0 | 9 | EX-4.4, EX-8.4, EX-8.9 (plafond retry.max_ms) |
| `registre-indisponible.json` | 18 | 104 | 2 | 9 | EX-4.5, EX-4.7, EX-8.4, EX-8.10, EX-8.12, EX-9.4, EX-9.6, EX-9.7 (AN-36, AN-40) |
| `redemarrage-reprise.json` | 6 | 25 | 9 | 9 | EX-8.5, EX-8.12 (AN-33) |
| `ots-mise-a-niveau.json` | 23 | 107 | 0 | 10 | EX-6.1, EX-6.6, EX-6.7, EX-8.11 (AN-41) |
| `preuve-de-vie.json` | 20 | 64 | 0 | 4 | EX-4.3 (countersign_idle), EX-4.6, EX-8.4 règle 3 |
| `file-pleine.json` | 12 | 45 | 100 | 103 | EX-8.5 règle 4, EX-4.4 |
| `prestataire-min-interval.json` | 18 | 90 | 0 | 9 | EX-8.7, EX-5.5, EX-4.4 (AN-39) |
| `refus-puis-preuve-de-vie.json` | 31 | 62 | 0 | 3 | undefined |
| `refus-puis-preuve-de-vie-redemarrage.json` | 13 | 30 | 2 | 3 | undefined |
| `file-perdue.json` | 12 | 72 | 0 | 7 | undefined |
| `bascule-epoque.json` | 5 | 21 | 8 | 8 | undefined |
| `bascule-epoque-fichier-perdu.json` | 6 | 23 | 2 | 5 | undefined |
| `registre-indisponible-cloture.json` | 72 | 156 | 0 | 9 | undefined |
| `mi-periode-impair.json` | 58 | 91 | 0 | 5 | undefined |
| `reponse-hors-profil.json` | 9 | 42 | 0 | 3 | undefined |
| `point-manquant.json` | 13 | 75 | 0 | 6 | undefined |

- `heure-nominale-reference` : Période 1 de l'exemple de référence de CT-1 (annexe A de CT-1) : points K1 à K4 de CT-1 §10.8, clôture à 14:00:00.250Z ; échéances D_1 à D_11 toutes les 300 s, la clôture tenant lieu de D_12 (EX-4.2, EX-4.3) ; registre, prestataire principal, serveur interne pour les points et calendriers tous joignables ; aucune reprise. Les réponses des prestataires sont des entrées de la trace (jetons représentés par leur SHA-256) ; l'horloge est injectée.
- `principal-injoignable` : Clôture de la période 1 de référence ; le prestataire principal ne répond pas : erreur de transport, 503 avec Retry-After 30 s, 408 rejoué immédiatement une fois, délai d'attente, 503 sans Retry-After ; attentes d'EX-8.9 (5 s + 100 ms de gigue, Retry-After 30 s, 0 s, 40 s + 200 ms, 80 s + 50 ms) ; relève par le secours 300 s après la première tentative (manifest.fallback_after_s, EX-8.8), jeton promu du secours ; la réponse tardive du principal à la tentative 6 est conservée sans être promue (EX-5.8, EX-8.5).
- `refus-permanent-releve` : Points contresignés par un prestataire de second rang : K1 reçoit PKIStatus 2 unacceptedPolicy, erreur permanente sans relève pour ce rôle (EX-5.7, EX-8.8) : demande refusee, alerte prestataires_epuises ; la demande refusée ne compte plus comme contresignée et rend la main à ses échéances D_1 à D_8 (EX-4.3, EX-8.4 règle 1) : K4, premier point qui suit, est contresigné pour D_1 à D_11 en une requête. À la clôture, le principal répond unacceptedPolicy : relève immédiate par le secours (la demande repasse a_envoyer, EX-8.3), aucune réexpédition de la requête refusée (EX-5.12).
- `reponse-tardive` : Période 2 de l'exemple de référence (points K5 et K6 sans nouvel événement, tree_size 0) : aucun point ancré ni contresigné, les onze échéances sont closes sans_objet au point de clôture (EX-4.3, countersign_idle faux). Le jeton de clôture arrive trois fois plus de max_response_delay_s (60 s) après l'envoi : les deux premières réponses sont conservées sans être promues et rejouées avec un nouveau nonce, la troisième est promue avec l'avertissement reponse_tardive (EX-5.11).
- `horloge-suspecte` : Comme la trace de référence, sans K2 ni K3 : le serveur interne répond pour K1 avec un genTime de 13:45:10 alors que la requête est partie à 13:42:03, soit 187 s d'écart, au-delà de clock_tolerance_s (120 s) : le jeton est promu, marqué horloge_suspecte, et l'alerte est levée (EX-5.11) ; d_jeton se lit sur la borne du jeton. K4 satisfait D_9 à D_11.
- `echeance-remplacee` : Le serveur interne ne répond pas à la requête de K1 (délai d'attente à chaque tentative ; retry.initial_ms porté à 60 s pour raccourcir la trace : attentes 60, 120, 240 puis 300 s plafonnées, gigue nulle) ; K2 est contresigné pour D_9 et D_10 : la demande de K1 et ses échéances D_1 à D_8 passent remplacee, la ligne checkpoint_anchor_late porte la fenêtre observée (borne du jeton de K2 moins D_1) et l'alerte est mineure pour le serveur interne (EX-4.4, EX-8.4). Aucun rattrapage des points ; la clôture est servie normalement.
- `registre-indisponible` : Redémarrage à 13:42:01 avec, dans la file, l'ancre de K1 envoyee sans reçu et sa demande de jeton en attente du registre (EX-8.12 : renvoi des mêmes octets, interrogation de l'inclusion). L'inclusion n'est pas constatée dans squat_wait_s (5 s) : la requête part avec la ligne ordre_ancres_non_respecte (EX-4.7, EX-9.6) ; l'ancre est renvoyée puis remplacée au même nonce à chaque inclusion_alert_s (300 s) avec l'alerte inclusion_late, puis le registre répond empreinte_squattee : demande refusee, alerte critique, aucun nouvel essai (EX-9.7). À la clôture, l'ancre de la période reste sans reçu : jeton_periode en attente_registre, registry_pending à chaque inclusion_alert_s, anchor_pending à queue.anchor_pending_alert_s (900 s), puis inclusion tardive et jeton de clôture (EX-4.5, EX-8.4).
- `redemarrage-reprise` : La trace de référence interrompue à 14:00:02.500 et redémarrée : la file porte le jeton de K4 envoyee (réponse non reçue), l'ancre de la période envoyee sans reçu, le jeton de clôture en attente_registre et la preuve OpenTimestamps en_attente. Transitions d'EX-8.12 : envoyee devient a_reprendre et repart aussitôt avec un nouveau nonce (tentative 2) ; l'ancre est renvoyée ; l'inclusion est interrogée ; la mise à niveau est reprogrammée à max(due_at, now). La réponse à la tentative 1 de K4, arrivée après le redémarrage, est conservée sans changer l'état (EX-8.5).
- `ots-mise-a-niveau` : Option mi_periode : K1, sélectionné par l'échéance médiane D_6, reçoit une preuve OpenTimestamps en plus de son ancre et de son jeton (EX-6.1) ; cadence de mise à niveau raccourcie (first_after_s et interval_s à 60 s). Soumission, attestation en attente, première mise à niveau sans attestation (404 : en_attente, nouvelle tentative interval_s plus tard), seconde mise à niveau avec attestation Bitcoin : preuve complète, réexport demandé (EX-6.6, EX-6.7, EX-8.11). La preuve de la clôture est soumise puis mise à niveau une fois sans attestation avant l'arrêt.
- `preuve-de-vie` : Période 2 de l'exemple de référence avec countersign_idle vrai : K5 et K6 n'engagent aucun nouvel événement (tree_size 0) et ne sont pas ancrés au registre (EX-4.6), mais le point de clôture K6, premier point de checkpoint_ts >= D_1 à D_11, est contresigné pour ces onze échéances en une requête, qui part aussitôt faute d'ancre à attendre (EX-4.3, EX-8.4 règle 3) ; puis la clôture est servie.
- `file-pleine` : queue.max_pending abaissé à 100 et une file qui porte déjà cent jetons de clôture en a_reprendre (cent heures de panne du prestataire, représentées ; prochaine tentative après la fin de la trace) : les points K1, K2 et K4 ne sont plus ancrés (anchor_queue_full, alerte file_pleine critique) mais la clôture crée toujours ses trois demandes et le jeton de clôture est obtenu (EX-8.5, règle 4). Les échéances de points restées ouvertes sont closes remplacee par la clôture (EX-4.4).
- `prestataire-min-interval` : Points contresignés par le prestataire principal dont min_interval_ms vaut 480 000 (huit minutes) : la requête de K2 (13:53:02) rend le prestataire indisponible jusqu'à 14:01:02 ; à la clôture, le jeton de K4 et le jeton de clôture attendent tous deux ; à 14:01:02 le jeton_periode part d'abord (EX-8.7) et le jeton de K4 est reprogrammé huit minutes plus tard ; la clôture obtenue avant lui clôt remplacee la demande de K4 et son échéance D_11 (EX-4.4), avec l'alerte majeure d'un prestataire extérieur.
- `refus-puis-preuve-de-vie` : Journal des vecteurs, période 1, points contresignés par un prestataire de second rang : le jeton du point de 09:15 (tree_size 5, D_3) est refusé (unacceptedPolicy, sans relève pour ce rôle) ; la demande refusée ne compte pas comme contresignée et rend D_3 (EX-4.3, EX-8.4 règle 1) : le point suivant, à 09:16, de même tree_size (preuve de vie), est contresigné pour D_3 au lieu d'être clos sans_objet ; D_4 et D_5 sont ensuite closes sans_objet (même tree_size qu'un point dont le jeton est obtenu).
- `refus-puis-preuve-de-vie-redemarrage` : Le scénario refus-puis-preuve-de-vie interrompu après le refus du jeton de 09:15 et redémarré à 09:15:30 sur sa file : la demande refusée ne tient aucune échéance au démarrage (EX-8.12) et le point de 09:16 est contresigné au même instant et auprès du même prestataire que sans redémarrage. Les échéances closes sans_objet ne sont pas dans la file : D_1 et D_2, rouvertes au démarrage, sont servies par le même jeton (sans requête de plus).
- `file-perdue` : Période 1 de l'exemple de référence : la file est perdue et le composant redémarre à 13:56 avec une file vide ; l'enregistreur relève dans son stockage les points K1 à K3 sans ancre obtenue (stockage_relu) : le dernier point de la période ouverte, K3, est traité comme admis (ancre au registre, jeton pour D_1 à D_10), anchoring_queue_rebuilt porte le nombre de demandes recréées et l'alerte file_perdue est levée (EX-8.12). La suite de l'heure est servie normalement.
- `bascule-epoque` : Bascule d'écrivain (CT-2 §13) sur le journal des vecteurs : l'écrivain d'époque 1 a clos la période 1 (ancre de la période envoyee sans reçu, jeton de clôture en attente_registre, preuve OpenTimestamps en attente) puis s'est arrêté ; l'écrivain d'époque 2 a servi les premiers points de la période 2 dans file-2.ndjson. Au redémarrage à 10:06, le composant relit tous les fichiers de file (file-1.ndjson puis file-2.ndjson, EX-8.12 ; reprise/bascule-epoque.epoque-*.ndjson) : la demande de jeton de clôture de l'époque 1 n'est pas oubliée ; la confrontation au stockage (stockage_relu) ne recrée aucune demande. L'ancre de la période est renvoyée, incluse, et le jeton qualifié obtenu (EX-4.5).
- `bascule-epoque-fichier-perdu` : Même bascule, file-1.ndjson perdu : seul file-2.ndjson est relu ; la confrontation au stockage (stockage_relu : manifeste de la période 1 sans ancre obtenue, points de la période 2) recrée les trois demandes de la clôture de la période 1 (EX-8.12 : le déclenchement ne dépend pas d'une file vide) ; anchoring_queue_rebuilt et alerte file_perdue ; le jeton de clôture est obtenu.
- `registre-indisponible-cloture` : Journal des vecteurs, période 1 (un point par minute) ; le registre n'inclut plus rien à partir de l'ancre du point de 09:13 (inclusion_alert_s porté à 1800 s pour raccourcir la trace). L'ancre du point de 09:32 attend la clé (a_envoyer) puis est remplacée par celle du point de clôture (EX-9.5, rattrapage). À la clôture, le jeton de la période attend l'inclusion de son ancre ; squat_wait_s après la clôture, le point de clôture (tree_size 9, aucune échéance ne l'a sélectionné) reçoit un jeton_point de repli auprès du prestataire des points (EX-4.2, EX-8.4 règle 2), envoyé squat_wait_s plus tard avec ordre_ancres_non_respecte, ce qui borne la date du dernier intervalle. Le registre revient à 10:20 : ancre de la période, jeton qualifié de la clôture, puis ancre du point de clôture.
- `mi-periode-impair` : Option mi_periode avec c_T = 720 s (n_T = 5, nombre impair) sur le journal des vecteurs : l'échéance médiane est k_m = 3 (D_3 = 09:36) et le point qu'elle sélectionne reçoit une preuve OpenTimestamps en plus de son jeton (EX-6.1) ; aucune preuve pour les autres points.
- `reponse-hors-profil` : Clôture de la période 1 de référence : le principal répond 200 avec un Content-Type text/html (type_contenu, erreur permanente : relève immédiate) ; le secours répond un jeton dont la politique est hors de accepted_policies (politique_refusee, permanente) : les deux prestataires sont épuisés, alerte prestataires_epuises, reprise au pas retry.max_ms en alternant (EX-8.8) ; le principal répond alors un corps de 200 000 octets (taille, permanente), puis le secours un jeton conforme, promu (EX-5.10, étapes 1 et 5 ; EX-8.6).
- `point-manquant` : Journal des vecteurs, période 1, dont l'enregistreur n'a produit que trois points (09:00, 09:59 et la clôture) : 2 x c_K après le point de 09:00 sans autre point, la ligne point_manquant et l'alerte majeure sont émises (EX-8.15) ; le point de 09:59 est sélectionné par D_1 à D_11 et contresigné en une requête (EX-4.3).

## reprise/ (EX-8.12, AN-33)

Files NDJSON (une demande par ligne, JCS intégral) avant et après le `demarrage` de deux traces : une seule demande par `id`, la dernière ligne fait foi.

- `registre-indisponible.avant.ndjson` (2 ligne(s)), `registre-indisponible.apres.ndjson` (9 ligne(s)) : file de `planification/registre-indisponible.json`.
- `redemarrage-reprise.avant.ndjson` (9 ligne(s)), `redemarrage-reprise.apres.ndjson` (9 ligne(s)) : file de `planification/redemarrage-reprise.json`.
- `file-pleine.avant.ndjson` (100 ligne(s)), `file-pleine.apres.ndjson` (103 ligne(s)) : file de `planification/file-pleine.json`.
- `refus-puis-preuve-de-vie-redemarrage.avant.ndjson` (2 ligne(s)), `refus-puis-preuve-de-vie-redemarrage.apres.ndjson` (3 ligne(s)) : file de `planification/refus-puis-preuve-de-vie-redemarrage.json`.
- `bascule-epoque.avant.ndjson` (8 ligne(s)), `bascule-epoque.apres.ndjson` (8 ligne(s)) : file de `planification/bascule-epoque.json`.
- `bascule-epoque-fichier-perdu.avant.ndjson` (2 ligne(s)), `bascule-epoque-fichier-perdu.apres.ndjson` (5 ligne(s)) : file de `planification/bascule-epoque-fichier-perdu.json`.

## cout/ (§12.3, AN-59, AN-60)

`cout.json` (`#/$defs/fichier_vecteurs`) : les onze cas de §12.3, six grandeurs par cas ; `p` est une unité symbolique.

| Cas | `N_q` | `N_s` | `N_a` (au plus) | Gaz (au plus) | `C_j` | `C` |
|---|---|---|---|---|---|---|
| `defaut-second-rang-a1` | 8760 | 96360 | 543120 | 55423030800 | 28032 p | 28032 p |
| `defaut-second-rang-a025` | 8760 | 24090 | 543120 | 55423030800 | 13578 p | 13578 p |
| `points-chez-principal-a025` | 32850 | 0 | 543120 | 55423030800 | 32850 p | 32850 p |
| `points-chez-principal-a1-dix-journaux` | 105120 | 0 | 543120 | 55423030800 | 105120 p | 1051200 p |
| `serveur-interne` | 8760 | 96360 | 543120 | 55423030800 | 8760 p | 8760 p |
| `forfait-avec-quota` | 8760 | 96360 | 543120 | 55423030800 | 29272 p | 29272 p |
| `forfait-depasse-points-principal` | 105120 | 0 | 543120 | 55423030800 | 105120 p | 105120 p |
| `sans-points` | 8760 | 0 | 8760 | 3602401080 | 8760 p | 8760 p |
| `preuve-de-vie` | 8760 | 96360 | 543120 | 55423030800 | 28032 p | 28032 p |
| `reprises-facturees` | 56940 | 0 | 543120 | 55423030800 | 62634 p | 62634 p |
| `cadence-une-minute-principal` | 527040 | 0 | 544608 | 55574874720 | 527040 p | 527040 p |

- `defaut-second-rang-a1` : Cadences par défaut, points contresignés par un prestataire de second rang à p_s = 0,2 p_q, activité a = 1, un journal.
- `defaut-second-rang-a025` : Idem, activité a = 0,25 (nouveaux événements à un quart des échéances).
- `points-chez-principal-a025` : Points contresignés par le prestataire principal (qualifié), a = 0,25.
- `points-chez-principal-a1-dix-journaux` : Points chez le principal, a = 1, dix journaux : les maxima de la table CT-5 §4.6.
- `serveur-interne` : Points contresignés par le serveur interne (p_s = 0) ; seule la clôture horaire est facturée.
- `forfait-avec-quota` : Forfait annuel F = 10 000 p couvrant Q = 10 000 jetons qualifiés, points chez le second rang à p_s = 0,2, a = 1.
- `forfait-depasse-points-principal` : Forfait F = 10 000 p, Q = 10 000, points chez le principal, a = 1 : dépassement facturé au jeton.
- `sans-points` : c_T = 3600 (aucun point contresigné) et aucune ancre de point au registre : coût de la version antérieure.
- `preuve-de-vie` : countersign_idle vrai : chaque échéance produit un jeton de second rang, quelle que soit l'activité.
- `reprises-facturees` : Dix pour cent de requêtes facturées en plus (r = 0,1), points chez le principal, a = 0,5.
- `cadence-une-minute-principal` : c_T = 60 (une échéance par minute), points chez le principal, a = 1, année bissextile (8 784 h).

