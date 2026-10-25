# Vecteurs de CT-4 — Registre

Produit par `scripts/vecteurs/generer-ct4.mjs` (`npm run vecteurs:ct4`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-4-registre.md`](../../CT-4-registre.md), annexe A. Rejoués par `test/registreCt4.test.js` avec l'implémentation de référence `scripts/lib/conventions-registre.mjs` ; confrontés par le vérificateur Go indépendant de `verificateur-independant/` (A.5).

## Format

Chaque fichier de famille est conforme à `operations-registre-v0.schema.json#/$defs/fichier_vecteurs` (EX-A.3) : `cases[]` porte `id`, `description`, `checks` (vérifications exercées), `input`, `expected` et `refusal` (première vérification en échec et son code, ou `null`).

- Pour une vérification RG-, `refusal.code` est un motif stable (table `MOTIFS_RG` de `scripts/lib/conventions-registre.mjs`) ; le verdict comparé est `echoue` sur cette vérification. Pour une OP- ou une CP-, c'est le code d'erreur de la spécification (7.11, 9.3) ; un document non conforme à son schéma est refusé en tête d'OP-6 (demandes) ou d'OP-4 (dossiers) avec `entree_illisible`.
- `expected` est `null` pour un refus, sauf : (a) famille `transactions`, tout cas dont `input.fields` est donné : `expected` porte la transaction recalculée et signée depuis `fields` (`signing_payload`, `signing_hash`, `y_parity`, `r`, `s`, `raw_transaction`, `transaction_hash`, `from`) même quand RG-15 échoue sur les frais, la chaîne, la limite de gaz ou l'objet (transactions de la capture de CT-6, EX-A.4, et cas `remplacement-insuffisant`, `autre-chaine`, `frais-nuls`, `frais-inegaux`, `limite-au-dela-2-24`, `approvisionnement-excessif`, `deploiement-avec-destinataire`) ; un cas donné par `raw_transaction` seule (`non-protegee`, `liste-acces`, `signature-s-haut`, `illisible`) a `expected` nul ; (b) familles `manifestes` et `capture` : `expected.verdicts` donne le verdict de chaque vérification et `refusal` la première en échec (et, pour `manifestes`, `expected.registry` l'ancre dérivée, nulle quand RG-20 échoue).
- Octets en hexadécimal minuscule préfixé `0x` ; entiers de 64 bits en chaînes décimales ; signatures `{ signer, v, r, s }` (`v` dans {27, 28}) ; `PeriodMeta` au format `#/$defs/meta_periode`.
- `transactions.json` : `input.fields` sont les champs signés (6.7.3), `input.signer_key` la clé (constantes), `input.raw_transaction` la transaction vérifiée, `input.context` le contexte de RG-15 (`objet` : `appel`, `deploiement`, `approvisionnement` ; `remplace` : frais de la transaction remplacée).
- `manifestes.json` : `input.directory` est le répertoire du cas ; `manifest`, `previous`, `genesis` et les fichiers de preuve désignés par `contracts[].evidence` y sont des chemins relatifs ; `input.registry`, quand il figure, est l'ancre à comparer (RG-20).
- `capture.json` : `input.directory` contient l'index et les réponses brutes ; `input.validators` désigne le jeu contre lequel CP-4 vérifie le certificat (`test/fixtures/certificat-commit/validators.json`, ou le jeu d'essai de `constantes.json`).

## Constantes (A.2)

Clés de test publiques, sans valeur : elles ne doivent jamais porter de NUR ni servir hors des tests. `constantes.json` les porte toutes.

| Grandeur | Valeur |
|---|---|
| Chaîne | identifiant EVM 2124, identifiant BFT `noortrace-2124-dev` |
| `curator_set_registry` | `0x172076e0166d1f9cc711c77adf8488051744980c` |
| `recorder_registry` | `0xbec49fa140acaa83533fb00a2bb19bddd0290f25` |
| `period_registry` | `0x4ee6ecad1c2dae9f525404de8555724e3c35d07b` |
| `attestation_registry` | `0xf4b146fba71f41e0592668ffbf264f1d186b2ca8` |
| CuratorSet de `assureur-demo` | `0xc0f115a19107322cfbf1cdbc7ea011c19ebdb4f8` |
| Jeu de validateurs | `test/fixtures/certificat-commit/validators.json`, hachage `0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751` |
| Genèse | `chain/config/alloc-dev.json`, SHA-256 `0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537` |
| Organisation, journal | `assureur-demo` (`0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab`), `journal-sinistres` (`0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164`) |
| Compte Hardhat 0 (`m/44'/60'/0'/0/0`) | adresse `0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`, clé `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| Compte Hardhat 1 (`m/44'/60'/0'/0/1`) | adresse `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`, clé `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| Compte Hardhat 2 (`m/44'/60'/0'/0/2`) | adresse `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`, clé `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |
| Compte Hardhat 3 (`m/44'/60'/0'/0/3`) | adresse `0x90f79bf6eb2c4f870365e785982e1f101e93b906`, clé `0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6` |
| Compte Hardhat 4 (`m/44'/60'/0'/0/4`) | adresse `0x15d34aaf54267db7d7c367839aaf71a00a2c6a65`, clé `0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a` |
| `rec-test-01` | clé de chaîne `0xaa2a59656361352e96ef2eed355316ef8b29dab7` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-01`)) = `0xda2e35b7f69680fe15647356186bbfc784c60620e57ef94abb6858299b26e4d0`) ; clé Ed25519 `0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-enregistreur/rec-test-01`))) |
| `rec-test-02` | clé de chaîne `0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-02`)) = `0xdfc0ece7f053fe30fb6e96ed3aa4432e9efa0007411e56a854fac7dadc0d68e6`) ; clé Ed25519 `0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-enregistreur/rec-test-02`))) |
| `rec-test-03` | clé de chaîne `0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-chaine/rec-test-03`)) = `0x7964474d727336e7b6f55f90182698a6ed2ad716c51ee9d1e4d09715912f7607`) ; clé Ed25519 `0x7fcebb9e8efd62d13a17c830ad33739c1de7fe9f1458701cb739ae15e9e62cd6` (graine SHA-256(UTF-8(`noortrace/vecteurs/v0/cle-enregistreur/rec-test-03`))) |
| Validateur d'essai `v1` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/validateur/v1`)) = `0xf9b48887af0347985e3e896450d23970554cc46ecde7c086e498e4df3e2b8517` ; clé publique `0x0447c93e2d29e5f1e1…` |
| Validateur d'essai `v2` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/validateur/v2`)) = `0xe6205565ff5d896a3629a49c4f1ab1a91f371d42fdbb344e77e228e5d4630523` ; clé publique `0x0475c8e9ede700907a…` |
| Validateur d'essai `v3` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/validateur/v3`)) = `0xe673e1ca9fd3584ee01b7a682fc2187fbe12f3cffa00b321b4a2192246d9bff6` ; clé publique `0x04094055b88fab5e51…` |
| Validateur d'essai `v4` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/validateur/v4`)) = `0x59ddb6f3304ce78f18c17a920698e31af5ce8ca887b76236df1a998a3dace930` ; clé publique `0x0414aba427dd5ddda8…` |
| Jeu d'essai | hachage `0x53e2cd91f5b84283514694f2dd31a5f060f712960cda90140bd7b8aaea33b0ac` |
| Instance synthétique de production, `tresorerie` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/compte/tresorerie`)), adresse `0xa95a82cc265f0d72f40cb040dfd644e74873d383` |
| Instance synthétique de production, `deployeur` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/compte/deployeur`)), adresse `0x3fe8b04d740f4830417565e9d6c0903620d36cbb` |
| Instance synthétique de production, `administrateur-registre` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/compte/administrateur-registre`)), adresse `0x71a272a1cf45cea193b923450a7af09a9f1586a5` |
| Instance synthétique de production, `relayeur` | graine SHA-256(UTF-8(`noortrace/vecteurs/ct4/compte/relayeur`)), adresse `0x526b68c91c74f6faa53d03d990fd97a79922d202` |
| Instance synthétique de production | identifiant EVM 1912124 (fictif), `noortrace-1912124-vecteur` ; code de création synthétique `0x600a600c600039600a6000f3602a60005260206000f3` |
| Exemples de 7.7 et 7.10 | `relecteur-exemple`, `journal-principal`, periodHash du manifeste d'exemple `0x266dd53a36a4c33232bd8dc4758eb036cc7adf8f483cb1ae8e7fc2a77034e8fb`, empreinte `0xe9d0f7920aa2156e93aab68d210ea95738d9631d9911b544063ecda33034c18c` |

## identifiants.json — famille `identifiants`

Slugs et noms de journal admis et refusés ; org_id et journal_id (RG-1, RG-2, 6.2, 6.3).

| Cas | Vérifications | Attendu |
|---|---|---|
| `slug-assureur-demo` | RG-1 | `org_id` `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` |
| `slug-canton-demo` | RG-1 | `org_id` `0x71917bc4f50a62e09e2bd4bd01f694e77b055c42fee74846e2469f5a79de3b88` |
| `slug-relecteur-exemple` | RG-1 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `slug-un-caractere` | RG-1 | `org_id` `0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb` |
| `slug-chiffres` | RG-1 | `org_id` `0x07cc400d9864958d2332d94cdffc692a845f67a5765b379c7f83fd89574c5af0` |
| `slug-64-caracteres` | RG-1 | `org_id` `0x9b5f39e3357ee060c6139a7e99d6e1c9933b5bbf8616ef7952b3a2d403187091` |
| `slug-e2e` | RG-1 | `org_id` `0x26c2999eb37b54abe4294a6b531dc32a8075b9e574e54ad8a506ab1b164bea03` |
| `slug-production` | RG-1 | `org_id` `0xe6652f9078e2c1261386a93de6ac5bfdd1316fc94195022953bd9b8ba9b950a0` |
| `slug-vide` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-65-caracteres` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-majuscule` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-tiret-en-tete` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-tiret-en-fin` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-espace` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-unicode` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-souligne` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-point` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `slug-production-forme` | RG-1 | `echoue` : RG-1 `slug_invalide` |
| `journal-principal` | RG-2 | `journal_id` `0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b` |
| `journal-sinistres` | RG-2 | `journal_id` `0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164` |
| `journal-01` | RG-2 | `journal_id` `0x4f59becfc6c93a0fec6b8383416cfc18c209cc0206cf6fe72e0ed678e5473997` |
| `journal-majuscule` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |
| `journal-souligne` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |
| `journal-espace` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |
| `journal-vide` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |
| `journal-tiret-en-tete` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |
| `journal-65-caracteres` | RG-2 | `echoue` : RG-2 `nom_journal_invalide` |

## doctypes.json — famille `doctypes`

Libellés et valeurs de docType admis et refusés (RG-3, 6.4).

| Cas | Vérifications | Attendu |
|---|---|---|
| `libelle-periode` | RG-3 | `doc_type` `0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee` |
| `valeur-periode` | RG-3 | `label` `noortrace/periode/v0` |
| `libelle-hors-table` | RG-3 | `echoue` : RG-3 `libelle_hors_table` |
| `libelle-version-suivante` | RG-3 | `echoue` : RG-3 `libelle_hors_table` |
| `libelle-majuscule` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-prefixe-majuscule` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-version-zero-de-tete` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-version-quatre-chiffres` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-sans-version` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-accent` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-espace-final` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-tiret-en-tete` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `libelle-segment-33` | RG-3 | `echoue` : RG-3 `libelle_invalide` |
| `valeur-nulle` | RG-3 | `echoue` : RG-3 `doctype_nul` |
| `valeur-hors-table` | RG-3 | `echoue` : RG-3 `doctype_hors_table` |

## empreintes.json — famille `empreintes`

Empreintes d'ancre keccak256(org_id ‖ journal_id ‖ periodHash) (RG-4, 6.5) ; égales à anchor_fingerprint de CT-1 pour ses trois manifestes.

| Cas | Vérifications | Attendu |
|---|---|---|
| `ct1-periode-1` | RG-4 | `fingerprint` `0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6` |
| `ct1-periode-2` | RG-4 | `fingerprint` `0xb924b06ebd452df9db27c7c29305d5d1fd876bdedc1e8483a6088f006ca68ee5` |
| `ct1-periode-3` | RG-4 | `fingerprint` `0xd46dec9a01a05df44217f6762249d4ea088290266ceb8046165721c9c85b21ca` |
| `exemple-relecteur` | RG-4 | `fingerprint` `0xe9d0f7920aa2156e93aab68d210ea95738d9631d9911b544063ecda33034c18c` |
| `autre-organisation` | RG-4 | `fingerprint` `0x76afb718d7d31e2f7a83750c013581b266118d837c90b3c21faf7c7ebdff5dc8` |
| `declaree-racine` | RG-4 | `echoue` : RG-4 `empreinte_differente` |
| `declaree-ordre-inverse` | RG-4 | `echoue` : RG-4 `empreinte_differente` |
| `declaree-sha256` | RG-4 | `echoue` : RG-4 `empreinte_differente` |
| `org-id-nul` | RG-4 | `echoue` : RG-4 `entree_nulle` |
| `journal-id-nul` | RG-4 | `echoue` : RG-4 `entree_nulle` |
| `period-hash-nul` | RG-4 | `echoue` : RG-4 `entree_nulle` |

## condenses.json — famille `condenses`

Champs de clôture (RG-5), six condensés internes et leurs préimages (RG-6 à RG-11), hachage signé et signatures (RG-12), jeux de signatures au seuil (RG-13), dont les cinq opérations au seuil de la capture de CT-6 (EX-A.4).

| Cas | Vérifications | Attendu |
|---|---|---|
| `cloture-periode-1` | RG-5 | `period_meta` conforme |
| `cloture-periode-2` | RG-5 | `period_meta` conforme |
| `cloture-periode-3-vide` | RG-5 | `period_meta` conforme |
| `cloture-uri-64` | RG-5 | `period_meta` conforme |
| `cloture-org-id-nul` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-journal-id-nul` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-period-hash-nul` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-bornes-inversees` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-period-end-max` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-last-seq-max` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-vide-racine` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-racine-nulle` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-sequence-invalide` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-discontinuite-temporelle` | RG-5 | `echoue` : RG-5 `discontinuite_temporelle` |
| `cloture-discontinuite-sequence` | RG-5 | `echoue` : RG-5 `discontinuite_sequence` |
| `cloture-uri-65` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-uri-non-imprimable` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-uri-slug` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `cloture-uri-journal` | RG-5 | `echoue` : RG-5 `periode_invalide` |
| `period-digest-periode-1` | RG-6 | `digest` `0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674` |
| `period-digest-periode-2` | RG-6 | `digest` `0xf861d8a4fa4983149295a463d5db30e3459ca9bfd6c39c2fd41e9cc6d81797cd` |
| `period-digest-periode-3` | RG-6 | `digest` `0xe106092d800f6af249e2d17c8074b9ddfacb91186ab8b2d98f7864e05541e41d` |
| `period-digest-uri` | RG-6 | `digest` `0x5dd8193ca55559282deab8d90f09cdc81fd2730bfe458c154e1edd3e922f1960` |
| `period-digest-exemple` | RG-6 | `digest` `0xd7dda9e39a7c6b24e46d7c6bd6bcdaeab7be5b59661ab0190744073118bc72ec` |
| `period-digest-autre-chaine` | RG-6 | `echoue` : RG-6 `condense_different` |
| `register-digest-rec-test-01` | RG-7 | `digest` `0x90362e40306221d7f95b803857dab38f80d1ddb9b59c51441f464cb0334d1108` |
| `register-digest-rec-test-02` | RG-7 | `digest` `0x988583b32ad01d2a52e87b138d35f4ed03aaa44fb8df7d2e9fdcb90d88308715` |
| `register-digest-rec-test-03` | RG-7 | `digest` `0x6f914533ea9f2f485b71363b1fa0bb61c4bf32cdf8806ed8a99c3cb97fc5d378` |
| `register-digest-rec-exemple-01` | RG-7 | `digest` `0xd0b3adc4a42e8b3d9efea626a0dcd526d88fce25c7ad9f1abc3f3577d49d00fa` |
| `register-digest-cle-chaine-nulle` | RG-7 | `echoue` : RG-7 `entree_invalide` |
| `register-digest-autre-contrat` | RG-7 | `echoue` : RG-7 `condense_different` |
| `revoke-digest-rec-test-01` | RG-8 | `digest` `0x63e4dfd071d6f365a39772d9ca34e9791f6426e9dfc654178d280c9a1152b9df` |
| `revoke-digest-rec-test-02` | RG-8 | `digest` `0x6c9a58efdcb77291a71bed8221c4b944abfa6ef622ca3ff9a0286bc505bb9fbf` |
| `revoke-digest-avant-inscription` | RG-8 | `echoue` : RG-8 `entree_invalide` |
| `revoke-digest-autre-inscription` | RG-8 | `echoue` : RG-8 `condense_different` |
| `anchor-digest-periode-1` | RG-9 | `digest` `0xb1eb8a317f588d9484ebf839effd88727b92525bdb487402c57a7f5a1fc8cbe9` |
| `anchor-digest-periode-2` | RG-9 | `digest` `0x6bca21ce1b6db2c4ad84b93e4b28134b7559a9131b1a0f5ff884eeb85d46295f` |
| `anchor-digest-periode-3` | RG-9 | `digest` `0x8916e2260a6b9cf6dc265ed364cb1e75a96482247f7b3dcf3685ffc96e2072e1` |
| `anchor-digest-autre-contrat` | RG-9 | `echoue` : RG-9 `condense_different` |
| `revoke-ancre-periode-1` | RG-10 | `digest` `0xe1100e481e9d291717ac6b562fe333948ef11a5f3996d1d16c515da6f7e5b8f5` |
| `revoke-ancre-etiquette-ancre` | RG-10 | `echoue` : RG-10 `condense_different` |
| `admin-op-add-curator` | RG-11 | `digest` `0x63fef0b3eeadd94dfcdb7fe206d25133c71cbd1780e0c88ef03467f53322011d` |
| `admin-op-remove-curator` | RG-11 | `digest` `0x47910cd45f8188c601f18a647a3246c867c69ef723666ea46cc2e0984fee11c9` |
| `admin-op-set-threshold` | RG-11 | `digest` `0x4d39ce830e6099401b4102ef6c99cee6fbee5593bdf889d3a5fd132dba70face` |
| `admin-op-propose-admin` | RG-11 | `digest` `0xd0840fa693828406974358cd14061f33c59a826cc51f954f39972f615b816be2` |
| `admin-op-accept-admin` | RG-11 | `digest` `0x7e476755b067b6ddac378452cf49164bc37d782e890b38fc48a7885b76b38108` |
| `admin-op-inconnue` | RG-11 | `echoue` : RG-11 `entree_invalide` |
| `admin-op-autre-nonce` | RG-11 | `echoue` : RG-11 `condense_different` |
| `signature-h1-inscription` | RG-12 | `recovered` `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` |
| `signature-h2-inscription` | RG-12 | `recovered` `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc` |
| `signature-capture-16668` | RG-12 | `recovered` `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` |
| `signature-ancre-rec-test-02` | RG-12 | `recovered` `0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49` |
| `signature-s-haut` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-v-29` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-v-0` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-r-nul` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-s-nul` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-r-hors-ordre` | RG-12 | `echoue` : RG-12 `signature_non_canonique` |
| `signature-sans-prefixe` | RG-12 | `echoue` : RG-12 `signataire_different` |
| `signature-signataire-declare-faux` | RG-12 | `echoue` : RG-12 `signataire_different` |
| `signature-hachage-signe-faux` | RG-12 | `echoue` : RG-12 `hachage_signe_different` |
| `seuil-h1-h2-ranges` | RG-12, RG-13 | `signers` 2 élément(s) |
| `seuil-h2-h3-ranges` | RG-12, RG-13 | `signers` 2 élément(s) |
| `seuil-ordre-inverse` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |
| `seuil-hors-jeu` | RG-12, RG-13 | `echoue` : RG-13 `signataire_hors_jeu` |
| `seuil-doublon` | RG-12, RG-13 | `echoue` : RG-13 `signataire_double` |
| `seuil-une-signature` | RG-12, RG-13 | `echoue` : RG-13 `nombre_signatures` |
| `seuil-trois-signatures` | RG-12, RG-13 | `echoue` : RG-13 `nombre_signatures` |
| `seuil-s-haut` | RG-12, RG-13 | `echoue` : RG-12 `signature_non_canonique` |
| `capture-16648-ordre` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |
| `capture-16652-ordre` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |
| `capture-16656-ordre` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |
| `capture-16668-ordre` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |
| `capture-16672-ordre` | RG-12, RG-13 | `echoue` : RG-13 `ordre_signatures` |

## appels.json — famille `appels`

Données d'appel des fonctions écrites par les outils et arguments de constructeur (RG-14, 6.7.2) ; pour chaque transaction de la capture de CT-6, la donnée de la transaction réelle (EX-A.4).

| Cas | Vérifications | Attendu |
|---|---|---|
| `capture-16648` | RG-14 | `calldata` `0x982f962ea581bb78871a286f5e48b724…26051613` |
| `capture-16652` | RG-14 | `calldata` `0x982f962ea581bb78871a286f5e48b724…2f3631ac` |
| `capture-16656` | RG-14 | `calldata` `0x982f962ea581bb78871a286f5e48b724…93233372` |
| `capture-16660` | RG-14 | `calldata` `0x73deb4ad3690909bba236fc912813a9b…9b8a42c4` |
| `capture-16664` | RG-14 | `calldata` `0x73deb4adb924b06ebd452df9db27c7c2…e8f69db3` |
| `capture-16668` | RG-14 | `calldata` `0x8af03732000000000000000000000000…7e1f9dfa` |
| `capture-16672` | RG-14 | `calldata` `0x8af03732000000000000000000000000…b68e8c45` |
| `register-recorder-ranges` | RG-14 | `calldata` `0x982f962ea581bb78871a286f5e48b724…c38bf511` |
| `revoke-recorder` | RG-14 | `calldata` `0x7b2025eaa581bb78871a286f5e48b724…51890f75` |
| `submit-period-uri` | RG-14 | `calldata` `0x8af03732000000000000000000000000…e0b7e3d9` |
| `set-curator-set` | RG-14 | `calldata` `0x53823884a581bb78871a286f5e48b724…9ebdb4f8` |
| `add-curator-signed` | RG-14 | `calldata` `0xd3dc8837000000000000000000000000…39cc179b` |
| `remove-curator-signed` | RG-14 | `calldata` `0xa7484439000000000000000000000000…9a941982` |
| `set-threshold-signed` | RG-14 | `calldata` `0xf4db2a99000000000000000000000000…6ac06387` |
| `propose-admin-signed` | RG-14 | `calldata` `0x34e182a6000000000000000000000000…ec9c162a` |
| `accept-admin-signed` | RG-14 | `calldata` `0x7af25fd9000000000000000000000000…1eaf1767` |
| `constructeur-curator-set` | RG-14 | `constructor_args` `0x000000000000000000000000f39fd6e5…1e93b906` |
| `constructeur-curator-set-registry` | RG-14 | `constructor_args` `0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266` |
| `constructeur-period-registry` | RG-14 | `constructor_args` `0x000000000000000000000000172076e0166d1f9cc711c77adf8488051744980c` |
| `constructeur-recorder-registry` | RG-14 | `constructor_args` `0x000000000000000000000000172076e0166d1f9cc711c77adf8488051744980c` |
| `constructeur-attestation-registry` | RG-14 | `constructor_args` `0x` |
| `anchor-donnees-alterees` | RG-14 | `echoue` : RG-14 `donnees_differentes` |
| `submit-period-position-uri` | RG-14 | `echoue` : RG-14 `donnees_differentes` |
| `anchor-v-hors-uint8` | RG-14 | `echoue` : RG-14 `entree_invalide` |

## transactions.json — famille `transactions`

Transactions de type 2 signées et transactions à refuser (RG-15, 6.7.3) ; transactions de la capture de CT-6 recalculées octet pour octet (EX-A.4).

| Cas | Vérifications | Attendu |
|---|---|---|
| `capture-16648` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16652` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16656` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16660` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16664` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16668` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `capture-16672` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `exemple-6-7-3` | RG-15 | `transaction_hash` `0xf78912922ae35ecc19994b2c3ed8d5d7c53cd3702bb5f03ce5455c6b54eb486b` |
| `cloture-cle-chaine` | RG-15 | `transaction_hash` `0x9ca955a7007e0181892d817b4a621c61b4b54920a6db215ad1b76c22969c4813` |
| `inscription-relayeur` | RG-15 | `transaction_hash` `0x18a888e516be9d6c022523c715c5f2c55c4186df748bd4b6ad6a324a4acf649c` |
| `assignation` | RG-15 | `transaction_hash` `0xb0b91260527b7f70330a3741303a3fb71945b929fb101f4d6658c806eb12ecda` |
| `approvisionnement` | RG-15 | `transaction_hash` `0xd8c7723f3ac6f61806e67b2553340d4ce125caf6e07ca7bd6b27d993639f4425` |
| `deploiement` | RG-15 | `transaction_hash` `0x2b98d738670d2e77f62f6347bb9db7db925dc350fc4c0e327d8c26a2bdc344e8` |
| `remplacement-2-wei` | RG-15 | `transaction_hash` `0xfb6cc05b2419c91983b2e532ddd488066b47193ed872f1f22961213a95869f1a` |
| `remplacement-3-wei` | RG-15 | `transaction_hash` `0x628dd6f897406c3bac550bd764105510587b182423799e768ac45eb5817216c9` |
| `remplacement-insuffisant` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `non-protegee` | RG-15 | `echoue` : RG-15 `type_non_admis` |
| `autre-chaine` | RG-15 | `echoue` : RG-15 `chaine_differente` |
| `frais-nuls` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `frais-inegaux` | RG-15 | `echoue` : RG-15 `frais_non_conformes` |
| `limite-au-dela-2-24` | RG-15 | `echoue` : RG-15 `limite_gaz` |
| `liste-acces` | RG-15 | `echoue` : RG-15 `liste_acces` |
| `signature-s-haut` | RG-15 | `echoue` : RG-15 `signature_non_canonique` |
| `illisible` | RG-15 | `echoue` : RG-15 `transaction_illisible` |
| `approvisionnement-excessif` | RG-15 | `echoue` : RG-15 `objet_non_conforme` |
| `deploiement-avec-destinataire` | RG-15 | `echoue` : RG-15 `objet_non_conforme` |

## manifestes/manifestes.json — famille `manifestes`

Manifestes d'instance valides et refusés : verdict de RG-16 à RG-20 et ancre registry dérivée (6.8, 4.8).

| Cas | Vérifications | Attendu |
|---|---|---|
| `developpement-exemple` | RG-16, RG-17, RG-18, RG-19, RG-20 | RG-16 reussi, RG-17 reussi, RG-18 reussi, RG-19 reussi, RG-20 reussi |
| `production-r1` | RG-16, RG-17, RG-18, RG-19, RG-20 | RG-16 reussi, RG-17 reussi, RG-18 reussi, RG-19 reussi, RG-20 reussi |
| `production-r2` | RG-16, RG-17, RG-18, RG-19, RG-20 | RG-16 reussi, RG-17 reussi, RG-18 reussi, RG-19 reussi, RG-20 reussi |
| `schema` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-16 `schema` |
| `revision-mal-chainee` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-16 `revision_mal_chainee` |
| `genese-sha256` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `genese_differente` |
| `ligne-regles` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `ligne_regles_differente` |
| `valset-hash` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-18 `valset_hash_different` |
| `domaine-de-panne` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-18 `domaine_de_panne` |
| `arguments-constructeur` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `arguments_constructeur` |
| `adresse-creation` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `adresse_creation` |
| `genese-invalide` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `genese_invalide` |
| `regles-absentes` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `regles_invalides` |
| `identifiants-incoherents` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `identifiants_incoherents` |
| `offre-differente` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-17 `offre_differente` |
| `jeu-invalide` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-18 `jeu_invalide` |
| `operateurs-incoherents` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-18 `operateurs_incoherents` |
| `intervalles-incoherents` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-18 `intervalles_incoherents` |
| `contrats-en-service` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `contrats_en_service` |
| `preuve-absente` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `preuve_absente` |
| `preuve-autre-role` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `preuve_invalide` |
| `deploiement-avec-destinataire` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-19 `preuve_invalide` |
| `ancre-conforme` | RG-16, RG-17, RG-18, RG-19, RG-20 | RG-16 reussi, RG-17 reussi, RG-18 reussi, RG-19 reussi, RG-20 reussi |
| `ancre-differente` | RG-16, RG-17, RG-18, RG-19, RG-20 | `echoue` : RG-20 `ancre_differente` |

## demandes/demandes.json — famille `demandes`

Demandes de signature (operations-registre-v0#/$defs/demande_signature) : schéma, OP-6 (condensé recalculé), OP-7 (signatures canoniques, recouvrées, distinctes, rangées, membres et seuil).

| Cas | Vérifications | Attendu |
|---|---|---|
| `inscription-rec-exemple-01` | OP-6, OP-7 | `digest` `0xd0b3adc4a42e8b3d9efea626a0dcd526d88fce25c7ad9f1abc3f3577d49d00fa` |
| `inscription-rec-test-01` | OP-6, OP-7 | `digest` `0x90362e40306221d7f95b803857dab38f80d1ddb9b59c51441f464cb0334d1108` |
| `cloture-periode-1` | OP-6, OP-7 | `digest` `0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674` |
| `revocation-rec-test-01` | OP-6, OP-7 | `digest` `0x63e4dfd071d6f365a39772d9ca34e9791f6426e9dfc654178d280c9a1152b9df` |
| `ancre-periode-1` | OP-6, OP-7 | `digest` `0xb1eb8a317f588d9484ebf839effd88727b92525bdb487402c57a7f5a1fc8cbe9` |
| `administration-jeu-propose-admin` | OP-6, OP-7 | `digest` `0xd0840fa693828406974358cd14061f33c59a826cc51f954f39972f615b816be2` |
| `schema-champ-en-trop` | OP-6, OP-7 | `echoue` : OP-6 `entree_illisible` |
| `schema-signature-v-0` | OP-6, OP-7 | `echoue` : OP-6 `entree_illisible` |
| `condense-altere` | OP-6, OP-7 | `echoue` : OP-6 `condense_different` |
| `champs-alteres` | OP-6, OP-7 | `echoue` : OP-6 `condense_different` |
| `autre-contrat` | OP-6, OP-7 | `echoue` : OP-6 `condense_different` |
| `autre-chaine` | OP-6, OP-7 | `echoue` : OP-6 `condense_different` |
| `eip191-faux` | OP-6, OP-7 | `echoue` : OP-6 `condense_different` |
| `signature-s-haut` | OP-6, OP-7 | `echoue` : OP-7 `signature_non_canonique` |
| `signataire-hors-jeu` | OP-6, OP-7 | `echoue` : OP-7 `signataire_hors_jeu` |
| `signatures-insuffisantes` | OP-6, OP-7 | `echoue` : OP-7 `signatures_insuffisantes` |
| `ordre-inverse` | OP-6, OP-7 | `echoue` : OP-7 `signature_non_canonique` |
| `signataire-double` | OP-6, OP-7 | `echoue` : OP-7 `signature_non_canonique` |
| `signataire-declare-faux` | OP-6, OP-7 | `echoue` : OP-7 `signataire_hors_jeu` |
| `ancre-autre-emetteur` | OP-6, OP-7 | `echoue` : OP-7 `signataire_hors_jeu` |

## inscription/inscription.json — famille `inscription`

Dossiers d'inscription (inscription-client-v0) à toutes les étapes, valides et refusés : schéma et OP-4.

| Cas | Vérifications | Attendu |
|---|---|---|
| `relecteur-exemple-fini` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-0-prepare` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-1-jeu-approbateurs` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-2-assignation` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-3-lecture-jeu` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-4-approvisionnement` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-5-inscription` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `relecteur-exemple-6-premiere-ancre` | OP-4 | `org_id` `0x15424c5b6d09deed88ad408275c50812e2c7cc9e142f746f936fc96b05d560fc` |
| `assureur-demo-prepare` | OP-4 | `org_id` `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` |
| `schema-seuil-nul` | OP-4 | `echoue` : OP-4 `entree_illisible` |
| `schema-slug` | OP-4 | `echoue` : OP-4 `entree_illisible` |
| `org-id-faux` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `journal-id-faux` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `membres-non-tries` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `membre-nul` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `seuil-superieur` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `administrateur-nul` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `administrateur-exploitant` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `slug-lisible-production` | OP-4 | `echoue` : OP-4 `jeu_invalide` |
| `classe-d-production` | OP-4 | `echoue` : OP-4 `cle_invalide` |

## capture/capture.json — famille `capture`

Captures des quatre transactions de la période 1 de la capture de CT-6 et variantes altérées : verdicts CP-2 à CP-6 (CP-4 hors ligne) ; export des parties (EX-9.8 à EX-9.10).

| Cas | Vérifications | Attendu |
|---|---|---|
| `periode-1-inscription-16648` | CP-2, CP-3, CP-4, CP-5, CP-6 | CP-2 reussi, CP-3 reussi, CP-4 reussi, CP-5 reussi, CP-6 reussi |
| `periode-1-inscription-16652` | CP-2, CP-3, CP-4, CP-5, CP-6 | CP-2 reussi, CP-3 reussi, CP-4 reussi, CP-5 reussi, CP-6 reussi |
| `periode-1-ancre-16660` | CP-2, CP-3, CP-4, CP-5, CP-6 | CP-2 reussi, CP-3 reussi, CP-4 reussi, CP-5 reussi, CP-6 reussi |
| `periode-1-cloture-16668` | CP-2, CP-3, CP-4, CP-5, CP-6 | CP-2 reussi, CP-3 reussi, CP-4 reussi, CP-5 reussi, CP-6 reussi |
| `cp2-entete-modifie` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-2 `capture_incomplete` |
| `cp2-hash-index` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-2 `capture_incomplete` |
| `cp2-recu-autre-bloc` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-2 `capture_incomplete` |
| `cp3-recu-falsifie` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-3 `capture_incomplete` |
| `cp3-recu-autre-transaction` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-3 `capture_incomplete` |
| `cp3-recu-autre-nom` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-6 `capture_incomplete` |
| `cp4-autre-jeu` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-4 `certificat_invalide` |
| `cp4-valset-hash-index` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-4 `certificat_invalide` |
| `cp4-certificat-autre-bloc` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-4 `certificat_invalide` |
| `cp5-autre-role` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-5 `capture_incomplete` |
| `cp5-journal-absent` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-5 `capture_incomplete` |
| `cp6-sha256-faux` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-6 `capture_incomplete` |
| `cp6-nom-hors-convention` | CP-2, CP-3, CP-4, CP-5, CP-6 | `echoue` : CP-6 `capture_incomplete` |
| `export-periode-1` | CP-2, CP-3, CP-4, CP-5, CP-6 | `reussi` |

