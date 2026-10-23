# Vecteurs CT-3 — approbations

Produit par `scripts/vecteurs/generer-ct3.mjs` (`npm run vecteurs:ct3`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-3-approbations.md`](../../CT-3-approbations.md), annexe A. Rejoués par `test/approbation.test.js` avec l'implémentation de référence `scripts/lib/approbation.mjs`.

Le générateur n'efface et ne réécrit que ses propres entrées de premier niveau (`constantes.json`, `INDEX.md`, `acceptation-attendu.json` et les répertoires `acceptation/`, `candidats/`, `decisions/`, `evaluation/`, `politiques/`, `politiques-invalides/`, `signatures/`, `tickets/`), jamais `verificateur-independant/` (EX-A.1). Une partie des attendus est posée par conception dans le générateur (règle, décision et ouverture de chaque demande ; état de chaque ticket après chaque pas, sort et raison de chaque entrée ; décision, signataires, motif et source de chaque remise ; tickets des fenêtres) et confrontée à l'implémentation de référence avant d'être écrite. Le reste (seuil et membres d'une remise, objet approval rendu à une ré-émission, bornes et restant des fenêtres, jeu des réponses nouveau) sort de l'implémentation de référence sans contrôle de conception : le vérificateur Go indépendant (`verificateur-independant/`) le recalcule.

## Constantes (A.2, `constantes.json`)

Clés de test **publiques** (mnémonique Hardhat) : elles ne doivent jamais porter de valeur.

| Grandeur | Valeur |
|---|---|
| Organisation | `assureur-demo`, `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` |
| Journal | `journal-approbations`, `0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1` |
| Versions de politique | `vecteurs-ct3-1`, `vecteurs-ct3-2` |
| Chaîne, registre | 2124, `0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1` |
| Jeux | 1 : `0x35312352c0065a3fc46ce14dba05df3fcee9fbc2` ; 2 : `0xfc6619bf29131ace4eb03178580ed2ac64a5fe3c` |
| Hachages synthétiques | bloc `noortrace/vecteurs/ct3/bloc/<h>`, demande `noortrace/vecteurs/ct3/demande/<k>`, événement `noortrace/vecteurs/ct3/evenement/<seq>` (SHA-256 de l'étiquette UTF-8) |
| Compte 1 | `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`, clé `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| Compte 2 | `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`, clé `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |
| Compte 3 | `0x90f79bf6eb2c4f870365e785982e1f101e93b906`, clé `0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6` |
| Compte 4 | `0x15d34aaf54267db7d7c367839aaf71a00a2c6a65`, clé `0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a` |
| Demandeur | `u.martin@assureur-demo.example`, détient le compte 3 |
| Instant de base | `2026-11-12T09:00:00.000Z` |

## politiques/ et politiques-invalides/ (A.4, AP-1 à AP-4)

| Politique valide | Contenu |
|---|---|
| `assureur.json` | Exemple complet de CT-3 §4.3, même valeur JSON (scénario de l'assureur de CT-1 et CT-2). |
| `assureur-permute.json` | La même politique, chaque objet avec ses membres en ordre inverse (AP-17). |
| `selection.json` | Sélecteurs : noms exacts, préfixe sap__*, * seul ; règle par défaut automatique refuse. |
| `pointeurs.json` | Pointeurs RFC 6901 : un outil par cas, règles automatique refuse (VRAI : refus, INDETERMINE : refus marqué, FAUX : défaut autorise). |
| `nombres.json` | Comparaisons décimales exactes et typage numérique, un outil par opérateur. |
| `chaines.json` | Égalité, appartenance, préfixe, suffixe, booléen, sans normalisation Unicode. |
| `logique.json` | Combinaisons all, any, none en logique de Kleene ; garde existe. |
| `niveaux.json` | Les trois niveaux, les rangs, l'égalité de rang, la règle par défaut, les fenêtres. |
| `bornes.json` | Bornes admises d'EX-4.2 : pointeur de 32 jetons, condition de 8 niveaux, 64 prédicats, contest_ms = expire_after_ms − 1. |
| `ordre.json` | Issues de même rang : la première règle du document est retenue, et d'elle viennent contest_ms, la fenêtre ouverte ou consommée (EX-4.9). |
| `ordre-inverse.json` | La politique ordre.json, règles en ordre inverse : même décision, autre règle retenue (EX-4.9). |

Attendus des politiques refusées : `politiques-invalides/attendu.json` (liste complète des erreurs, triée par pointeur puis par code).

| Politique refusée | environment, expire_after_ms | Erreurs | Ce qu'elle exerce |
|---|---|---|---|
| `schema-version.json` | developpement, 3600000 | schema | version 1 : la constante du format est 0. |
| `schema-membre-inconnu.json` | developpement, 3600000 | schema | Membre de premier niveau non admis. |
| `schema-decision-manquante.json` | developpement, 3600000 | schema | Règle automatique sans décision. |
| `schema-fenetre-sans-window.json` | developpement, 3600000 | schema | Règle fenetre sans window. |
| `schema-defaut-fenetre.json` | developpement, 3600000 | schema | La règle par défaut ne peut pas être de niveau fenetre. |
| `schema-litteral-nombre.json` | developpement, 3600000 | schema | Littéral numérique écrit en nombre JSON : toujours une chaîne D. |
| `schema-litteral-exposant.json` | developpement, 3600000 | schema | Littéral "5e3" hors de la grammaire D. |
| `schema-joker-interne.json` | developpement, 3600000 | schema | Joker ailleurs qu'en fin de sélecteur : aucun autre joker n'existe. |
| `schema-double-joker.json` | developpement, 3600000 | schema | Deux jokers finaux. |
| `schema-pointeur-hors-arguments.json` | developpement, 3600000 | schema | Pointeur qui ne commence pas par /arguments. |
| `schema-pointeur-echappement.json` | developpement, 3600000 | schema | Échappement ~2 invalide (RFC 6901). |
| `schema-nom-crochet.json` | developpement, 3600000 | schema | Crochet dans un nom de règle. |
| `schema-nom-espace-final.json` | developpement, 3600000 | schema | Espace en fin de nom. |
| `schema-expression-reguliere.json` | developpement, 3600000 | schema | Opérateur d'expression régulière : le langage n'en a pas (EX-4.13). |
| `schema-statique-avec-chaine.json` | developpement, 3600000 | schema | Jeu statique qui porte un chain_id (nul exigé pour statique). |
| `schema-erreurs-multiples.json` | developpement, 3600000 | schema | Quatre non-conformités au schéma : une seule entrée schema. |
| `schema-et-nom-double.json` | developpement, 3600000 | schema | Non conforme au schéma (version 1) et nom en double : exactement l'entrée schema, aucune autre règle n'est vérifiée (EX-4.2). |
| `nom-double.json` | developpement, 3600000 | nom_double `/rules/2/name` | La troisième règle reprend le nom de la première (exemple de CT-3 annexe A.4). |
| `nom-de-la-regle-par-defaut.json` | developpement, 3600000 | nom_double `/rules/1/name` | Une règle porte le nom de la règle par défaut. |
| `pointeur-trop-long.json` | developpement, 3600000 | pointeur_trop_long `/rules/1/when/path` ; pointeur_trop_long `/rules/2/window/same_arguments/0` | Pointeurs de 33 jetons, dans un prédicat et dans same_arguments. |
| `condition-trop-profonde.json` | developpement, 3600000 | condition_trop_profonde `/rules/1/when` | Condition de 9 niveaux. |
| `trop-de-predicats.json` | developpement, 3600000 | trop_de_predicats `/rules/1/when` | 65 prédicats dans une règle. |
| `substitut-isole.json` | developpement, 3600000 | substitut_isole `/rules/1/description` | Substitut isolé U+D800 dans une description (écrit \ud800 dans le fichier). |
| `launched-by-double.json` | developpement, 3600000 | launched_by_double `/separation/identities/2/launched_by` | Le même launched_by deux fois dans separation.identities. |
| `contest-ms-egal-echeance.json` | developpement, 3600000 | contest_ms_trop_long `/rules/1/contest_ms` | contest_ms égal à expire_after_ms (3 600 000). |
| `contest-ms-defaut.json` | developpement, 600000 | contest_ms_trop_long `/default/contest_ms` | Règle par défaut à contest_ms 900 000 sous expire_after_ms 600 000. |
| `statique-seuil-incoherent.json` | developpement, 3600000 | seuil_statique_incoherent `/approver_set/threshold` | Jeu statique de trois membres déclaré de taille 4 (EX-8.2, point 1). |
| `statique-en-production.json` | production, 3600000 | jeu_statique_en_production `/approver_set/source` | Jeu statique chargé en production (EX-8.2, point 2). |
| `erreurs-multiples.json` | production, 3600000 | jeu_statique_en_production `/approver_set/source` ; seuil_statique_incoherent `/approver_set/threshold` ; contest_ms_trop_long `/rules/2/contest_ms` ; nom_double `/rules/2/name` ; launched_by_double `/separation/identities/1/launched_by` | Cinq erreurs au-delà du schéma : la liste complète, triée par pointeur puis par code. |
| `ordre-des-pointeurs.json` | developpement, 3600000 | nom_double `/rules/10/name` ; nom_double `/rules/2/name` | Onze règles, noms en double aux indices 2 et 10 : les pointeurs se trient comme des chaînes (« /rules/10 » avant « /rules/2 »), sans ordre numérique des indices (A.4). |

## evaluation/ (A.4, AP-5 à AP-17)

### `assureur.json` — politique `politiques/assureur.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `lecture-inconditionnelle` | `crm.claims.get` | autorise | `outil crm.claims.get : lecture autorisee` | — |
| `paiement-7400` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `beneficiaire-hors-liste` | `sap.payments.create` | refuse | `beneficiaire hors liste blanche` | — |
| `paiement-800` | `sap.payments.create` | autorise | `paiement <= 1000 CHF` | — |
| `paiement-2500-sans-fenetre` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-2500-fenetre-ouverte` | `sap.payments.create` | autorise | `paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]` | — |
| `paiement-2500-autre-beneficiaire` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-5000-borne` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-5000-dix-huit-decimales` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `paiement-nombre-entier` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `paiement-nombre-non-entier` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-hors-grammaire` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-montant-absent` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-devise-absente` | `sap.payments.create` | refuse | `paiement hors CHF [indetermine]` | — |
| `paiement-devise-minuscules` | `sap.payments.create` | refuse | `paiement hors CHF` | — |
| `paiement-iban-absent-fenetre` | `sap.payments.create` | refuse | `beneficiaire hors liste blanche [indetermine]` | — |
| `paiement-zero` | `sap.payments.create` | a_approuver | `defaut : revue` | — |
| `paiement-moins-zero` | `sap.payments.create` | a_approuver | `defaut : revue` | — |
| `courriel-assure` | `mail.send` | autorise | `outil mail.send : envoi autorise vers l'assure` | — |
| `courriel-garage` | `mail.send` | a_approuver | `defaut : revue` | — |
| `courriel-sans-role` | `mail.send` | a_approuver | `defaut : revue` | — |
| `outil-sans-regle` | `sap.payments.list` | a_approuver | `defaut : revue` | — |
| `outil-casse` | `SAP.payments.create` | a_approuver | `defaut : revue` | — |
| `suppression` | `crm.claims.delete` | a_approuver | `suppression de sinistre` | — |

### `assureur-permute.json` — politique `politiques/assureur-permute.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `lecture-inconditionnelle` | `crm.claims.get` | autorise | `outil crm.claims.get : lecture autorisee` | — |
| `paiement-7400` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `beneficiaire-hors-liste` | `sap.payments.create` | refuse | `beneficiaire hors liste blanche` | — |
| `paiement-800` | `sap.payments.create` | autorise | `paiement <= 1000 CHF` | — |
| `paiement-2500-sans-fenetre` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-2500-fenetre-ouverte` | `sap.payments.create` | autorise | `paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]` | — |
| `paiement-2500-autre-beneficiaire` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-5000-borne` | `sap.payments.create` | a_approuver | `paiement de 1000 a 5000 CHF` | oui |
| `paiement-5000-dix-huit-decimales` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `paiement-nombre-entier` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF` | — |
| `paiement-nombre-non-entier` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-hors-grammaire` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-montant-absent` | `sap.payments.create` | a_approuver | `paiement > 5000 CHF [indetermine]` | — |
| `paiement-devise-absente` | `sap.payments.create` | refuse | `paiement hors CHF [indetermine]` | — |
| `paiement-devise-minuscules` | `sap.payments.create` | refuse | `paiement hors CHF` | — |
| `paiement-iban-absent-fenetre` | `sap.payments.create` | refuse | `beneficiaire hors liste blanche [indetermine]` | — |
| `paiement-zero` | `sap.payments.create` | a_approuver | `defaut : revue` | — |
| `paiement-moins-zero` | `sap.payments.create` | a_approuver | `defaut : revue` | — |
| `courriel-assure` | `mail.send` | autorise | `outil mail.send : envoi autorise vers l'assure` | — |
| `courriel-garage` | `mail.send` | a_approuver | `defaut : revue` | — |
| `courriel-sans-role` | `mail.send` | a_approuver | `defaut : revue` | — |
| `outil-sans-regle` | `sap.payments.list` | a_approuver | `defaut : revue` | — |
| `outil-casse` | `SAP.payments.create` | a_approuver | `defaut : revue` | — |
| `suppression` | `crm.claims.delete` | a_approuver | `suppression de sinistre` | — |

### `selection.json` — politique `politiques/selection.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `nom-exact` | `crm__claims.get` | autorise | `lecture crm autorisee` | — |
| `nom-exact-casse` | `CRM__claims.get` | refuse | `defaut : refus` | — |
| `prefixe` | `sap__payments.create` | a_approuver | `ecritures sap en revue` | — |
| `prefixe-seul` | `sap__` | a_approuver | `ecritures sap en revue` | — |
| `prefixe-autre-alias` | `sapx__payments.create` | refuse | `defaut : refus` | — |
| `prefixe-un-seul-trait-bas` | `sap_payments.create` | refuse | `defaut : refus` | — |
| `etoile` | `mail__send` | refuse | `suppressions refusees` | — |
| `etoile-rang` | `crm__claims.get` | refuse | `suppressions refusees` | — |
| `etoile-garde` | `mail__send` | refuse | `defaut : refus` | — |
| `etoile-autre-action` | `mail__send` | refuse | `defaut : refus` | — |

### `pointeurs.json` — politique `politiques/pointeurs.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `barre-membre` | `ptr__barre` | refuse | `echappement ~1` | — |
| `barre-imbrique` | `ptr__barre` | refuse | `echappement ~1 [indetermine]` | — |
| `tilde-membre` | `ptr__tilde` | refuse | `echappement ~0` | — |
| `ordre-de-decodage` | `ptr__ordre` | refuse | `ordre de decodage` | — |
| `ordre-de-decodage-inverse` | `ptr__ordre` | refuse | `ordre de decodage [indetermine]` | — |
| `indice` | `ptr__indice` | refuse | `indice de tableau` | — |
| `indice-autre-valeur` | `ptr__indice` | autorise | `defaut : autorisation` | — |
| `membre-nul` | `ptr__nul` | refuse | `membre nul` | — |
| `membre-absent` | `ptr__nul` | autorise | `defaut : autorisation` | — |
| `jeton-tiret` | `ptr__tiret` | refuse | `jeton tiret [indetermine]` | — |
| `zero-de-tete-tableau` | `ptr__zero` | refuse | `zero de tete [indetermine]` | — |
| `zero-de-tete-objet` | `ptr__zero` | refuse | `zero de tete` | — |
| `dix-chiffres-objet` | `ptr__long` | refuse | `jeton de dix chiffres` | — |
| `dix-chiffres-tableau` | `ptr__long` | refuse | `jeton de dix chiffres [indetermine]` | — |
| `indice-hors-limites` | `ptr__hors` | refuse | `indice hors limites [indetermine]` | — |
| `pas-a-travers-une-chaine` | `ptr__chaine` | refuse | `pas a travers une chaine [indetermine]` | — |
| `membre-de-nom-vide` | `ptr__vide` | refuse | `membre de nom vide` | — |
| `membre-numerique-objet` | `ptr__objet` | refuse | `membre de nom numerique` | — |
| `membre-numerique-tableau` | `ptr__objet` | refuse | `membre de nom numerique` | — |

### `nombres.json` — politique `politiques/nombres.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `egal-chaine` | `num__egal` | refuse | `egal a 5000` | — |
| `egal-echelle` | `num__egal` | refuse | `egal a 5000` | — |
| `egal-nombre` | `num__egal` | refuse | `egal a 5000` | — |
| `egal-dix-huit-decimales` | `num__egal` | autorise | `defaut : autorisation` | — |
| `zero-negatif` | `num__zero` | refuse | `egal a zero` | — |
| `zero-negatif-decimales` | `num__zero` | refuse | `egal a zero` | — |
| `zero-nombre` | `num__zero` | refuse | `egal a zero` | — |
| `superieur-d-un-pas` | `num__sup` | refuse | `superieur a 5000` | — |
| `superieur-egalite` | `num__sup` | autorise | `defaut : autorisation` | — |
| `superieur-ordre-des-chaines` | `num__neuf` | refuse | `superieur a 9.00` | — |
| `superieur-ou-egal-borne` | `num__supeg` | refuse | `superieur ou egal a -0.5` | — |
| `superieur-ou-egal-sous-la-borne` | `num__supeg` | autorise | `defaut : autorisation` | — |
| `superieur-ou-egal-negatif-entier` | `num__supeg` | autorise | `defaut : autorisation` | — |
| `inferieur-negatif` | `num__inf` | refuse | `inferieur a zero` | — |
| `inferieur-plus-petit-pas` | `num__inf` | refuse | `inferieur a zero` | — |
| `inferieur-moins-zero` | `num__inf` | autorise | `defaut : autorisation` | — |
| `inferieur-ou-egal-pas` | `num__infeg` | refuse | `inferieur ou egal au plus petit pas` | — |
| `inferieur-ou-egal-deux-pas` | `num__infeg` | autorise | `defaut : autorisation` | — |
| `quarante-huit-chiffres` | `num__grand` | refuse | `superieur a trente chiffres` | — |
| `trente-et-un-chiffres` | `num__grand` | refuse | `superieur a trente chiffres [indetermine]` | — |
| `dix-neuf-decimales` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `entier-sur-maximal` | `num__sup` | refuse | `superieur a 5000` | — |
| `entier-hors-intervalle` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `nombre-non-entier` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `separateur-de-milliers` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `exposant` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `espace-de-tete` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `signe-plus` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `zero-de-tete` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `point-de-tete` | `num__supeg` | refuse | `superieur ou egal a -0.5 [indetermine]` | — |
| `point-final` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `booleen` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `nul` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `objet` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |
| `absent` | `num__sup` | refuse | `superieur a 5000 [indetermine]` | — |

### `chaines.json` — politique `politiques/chaines.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `egal` | `str__devise` | refuse | `devise CHF` | — |
| `egal-casse` | `str__devise` | autorise | `defaut : autorisation` | — |
| `egal-nombre` | `str__devise` | refuse | `devise CHF [indetermine]` | — |
| `egal-booleen` | `str__devise` | refuse | `devise CHF [indetermine]` | — |
| `egal-nul` | `str__devise` | refuse | `devise CHF [indetermine]` | — |
| `egal-absent` | `str__devise` | refuse | `devise CHF [indetermine]` | — |
| `sans-normalisation` | `str__accent` | refuse | `accent precompose` | — |
| `sans-normalisation-decompose` | `str__accent` | autorise | `defaut : autorisation` | — |
| `dans` | `str__liste` | refuse | `liste blanche` | — |
| `dans-hors-liste` | `str__liste` | autorise | `defaut : autorisation` | — |
| `dans-autre-type` | `str__liste` | refuse | `liste blanche [indetermine]` | — |
| `commence-par` | `str__prefixe` | refuse | `prefixe de compte` | — |
| `commence-par-casse` | `str__prefixe` | autorise | `defaut : autorisation` | — |
| `commence-par-tableau` | `str__prefixe` | refuse | `prefixe de compte [indetermine]` | — |
| `finit-par` | `str__domaine` | refuse | `domaine du courriel` | — |
| `finit-par-autre-domaine` | `str__domaine` | autorise | `defaut : autorisation` | — |
| `booleen-vrai` | `str__drapeau` | refuse | `drapeau urgent` | — |
| `booleen-faux` | `str__drapeau` | autorise | `defaut : autorisation` | — |
| `booleen-chaine` | `str__drapeau` | refuse | `drapeau urgent [indetermine]` | — |
| `suffixe-hors-plan-de-base` | `str__symbole` | refuse | `symbole hors du plan de base` | — |
| `suffixe-hors-plan-de-base-en-tete` | `str__symbole` | autorise | `defaut : autorisation` | — |

### `logique.json` — politique `politiques/logique.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `tout-vrai` | `log__tout` | refuse | `toutes` | — |
| `tout-faux` | `log__tout` | autorise | `defaut : autorisation` | — |
| `tout-indetermine` | `log__tout` | refuse | `toutes [indetermine]` | — |
| `tout-indetermine-inverse` | `log__tout` | refuse | `toutes [indetermine]` | — |
| `tout-faux-absorbe` | `log__tout` | autorise | `defaut : autorisation` | — |
| `tout-faux-absorbe-inverse` | `log__tout` | autorise | `defaut : autorisation` | — |
| `un-vrai-absorbe` | `log__un` | refuse | `l'une` | — |
| `un-vrai-absorbe-inverse` | `log__un` | refuse | `l'une` | — |
| `un-faux` | `log__un` | autorise | `defaut : autorisation` | — |
| `un-indetermine` | `log__un` | refuse | `l'une [indetermine]` | — |
| `un-inverse-vrai` | `log__un_inverse` | refuse | `l'une, ordre inverse` | — |
| `un-inverse-indetermine` | `log__un_inverse` | refuse | `l'une, ordre inverse [indetermine]` | — |
| `aucun-vrai` | `log__aucun` | refuse | `aucune` | — |
| `aucun-faux` | `log__aucun` | autorise | `defaut : autorisation` | — |
| `aucun-faux-inverse` | `log__aucun` | autorise | `defaut : autorisation` | — |
| `aucun-indetermine` | `log__aucun` | refuse | `aucune [indetermine]` | — |
| `imbriquee-vrai` | `log__imbrique` | refuse | `imbriquee` | — |
| `imbriquee-faux` | `log__imbrique` | autorise | `defaut : autorisation` | — |
| `imbriquee-existe` | `log__imbrique` | refuse | `imbriquee` | — |
| `imbriquee-indetermine` | `log__imbrique` | refuse | `imbriquee [indetermine]` | — |
| `garde-absent` | `log__garde` | autorise | `defaut : autorisation` | — |
| `garde-haute` | `log__garde` | refuse | `garde existe` | — |
| `garde-basse` | `log__garde` | autorise | `defaut : autorisation` | — |
| `garde-autre-type` | `log__garde` | refuse | `garde existe [indetermine]` | — |

### `niveaux.json` — politique `politiques/niveaux.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `automatique-autorise-egalite-de-rang` | `pay__virement` | autorise | `petit montant` | — |
| `fenetre-portee-indeterminee` | `pay__virement` | a_approuver | `fenetre moyenne [indetermine]` | — |
| `fenetre-ouvrante` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-couverte` | `pay__virement` | autorise | `fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]` | — |
| `fenetre-dernier-appel` | `pay__virement` | autorise | `fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]` | — |
| `fenetre-epuisee` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-debut-inclus` | `pay__virement` | autorise | `fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]` | — |
| `fenetre-fin-exclue` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-autre-demandeur` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-autre-beneficiaire` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-autre-version` | `pay__virement` | a_approuver | `fenetre moyenne` | oui |
| `fenetre-non-consommee` | `pay__virement` | refuse | `blocage pays` | — |
| `revue` | `pay__virement` | a_approuver | `revue elevee` | — |
| `revue-egalite-de-rang` | `pay__virement` | a_approuver | `revue elevee` | — |
| `refus` | `pay__virement` | refuse | `blocage pays` | — |
| `refus-indetermine` | `pay__virement` | refuse | `blocage pays [indetermine]` | — |
| `montant-absent` | `pay__virement` | a_approuver | `revue elevee [indetermine]` | — |
| `defaut-autre-outil` | `pay__inconnu` | a_approuver | `defaut : revue` | — |
| `consultation` | `pay__consultation` | autorise | `consultation autorisee` | — |
| `consultation-faux` | `pay__consultation` | a_approuver | `defaut : revue` | — |
| `consultation-indeterminee` | `pay__consultation` | a_approuver | `defaut : revue` | — |
| `fenetre-sans-portee-ouvrante` | `pay__releve` | a_approuver | `fenetre sans portee` | oui |
| `fenetre-sans-portee-couverte` | `pay__releve` | autorise | `fenetre sans portee [fenetre apr-0043 2026-11-12T10:05:00.000Z]` | — |
| `fenetre-autre-outil` | `pay__releve_detail` | a_approuver | `fenetre sans portee` | oui |

### `bornes.json` — politique `politiques/bornes.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `pointeur-32-jetons` | `borne__pointeur` | refuse | `pointeur de 32 jetons` | — |
| `condition-8-niveaux` | `borne__profondeur` | refuse | `condition de 8 niveaux` | — |
| `64-predicats` | `borne__predicats` | refuse | `64 predicats` | — |
| `64-predicats-un-absent` | `borne__predicats` | a_approuver | `defaut : revue` | — |

### `ordre.json` — politique `politiques/ordre.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `revue-meme-rang` | `ord__revue` | a_approuver | `revue sans contestation` | — |
| `fenetre-meme-rang` | `ord__fenetre` | a_approuver | `fenetre indeterminee [indetermine]` | — |
| `fenetres-couvrantes` | `ord__couverte` | autorise | `fenetre longue [fenetre apr-0051 2026-11-12T10:30:00.000Z]` | — |

### `ordre-inverse.json` — politique `politiques/ordre-inverse.json`

| Cas | Outil | Décision | policy.rule | Ouvrant |
|---|---|---|---|---|
| `revue-meme-rang` | `ord__revue` | a_approuver | `revue avec contestation` | — |
| `fenetre-meme-rang` | `ord__fenetre` | a_approuver | `fenetre determinee` | oui |
| `fenetres-couvrantes` | `ord__couverte` | autorise | `fenetre courte [fenetre apr-0052 2026-11-12T10:05:00.000Z]` | — |

## candidats/ (A.4, AP-16)

| Fichier | Cas | Liste L | approval_candidates |
|---|---|---|---|
| `assureur.json` | `exemple-4-12` | `crm.claims.get`, `crm.claims.delete`, `documents.search`, `mail.send`, `sap.payments.create`, `sap.payments.list` | `crm.claims.delete`, `mail.send`, `sap.payments.create`, `sap.payments.list` |
| `assureur.json` | `ordre-et-doublons` | `sap.payments.list`, `crm.claims.get`, `sap.payments.list`, `mail.send`, `documents.search`, `crm.claims.delete`, `mail.send` | `sap.payments.list`, `mail.send`, `crm.claims.delete` |
| `assureur.json` | `liste-vide` | — | — |
| `assureur.json` | `outil-inconnu` | `erp.invoices.cancel` | `erp.invoices.cancel` |
| `pointeurs.json` | `defaut-autorise` | `ptr__barre`, `ptr__autre`, `ptr__nul`, `ptr__barre` | `ptr__barre`, `ptr__nul` |
| `selection.json` | `regle-etoile-refus` | `crm__claims.get`, `mail__send`, `CRM__claims.get` | `crm__claims.get`, `mail__send`, `CRM__claims.get` |
| `niveaux.json` | `defaut-revue` | `pay__virement`, `pay__consultation`, `pay__releve`, `pay__inconnu` | `pay__virement`, `pay__consultation`, `pay__releve`, `pay__inconnu` |
| `nombres.json` | `regles-de-refus` | `num__egal`, `num__autre`, `num__grand` | `num__egal`, `num__grand` |

## acceptation/ et acceptation-attendu.json (A.5)

Le répertoire `acceptation/` est ce que reçoit chaque relecteur (consigne, politique, dix cas, gabarit de réponse) ; les décisions attendues sont dans `acceptation-attendu.json`, à côté, que les relecteurs ne reçoivent pas. Pour cette raison, cet index ne les reproduit pas : il dit seulement ce que chaque cas exerce.

| Cas | Ce qu'il exerce |
|---|---|
| `cas-01` | montant ordinaire sous la borne |
| `cas-02` | égalité exacte à la borne (≤ 1000) |
| `cas-03` | juste au-dessus de la borne |
| `cas-04` | autre devise |
| `cas-05` | argument absent : la règle restrictive s'applique |
| `cas-06` | montant en nombre JSON non entier : non numérique |
| `cas-07` | outil qu'aucune règle ne couvre : règle par défaut |
| `cas-08` | aucune règle ne s'applique (> 0 FAUX) |
| `cas-09` | montant en nombre JSON entier : numérique |
| `cas-10` | devise d'un autre type (nombre 756) : INDETERMINE |

## tickets/ (A.6, TK-1 à TK-13)

Chaque pas donne l'état de chaque ticket après l'entrée (minuteurs échus compris). Notation : entrée, instant, puis états ; « refus : » donne la raison d'une entrée refusée ; « remise : » la décision remise au noyau pendant le pas.

### `approuve-sans-contestation.json` (TK-1, TK-2, TK-3, TK-5, TK-7, TK-8, TK-9, TK-10, TK-12)

Cycle nominal : réservation (la réponse nouveau porte le jeu de repli), ouverture, gel du jeu 1 à la hauteur 1200, votes approuve des comptes 1 et 2, confirmation à 1214, remise, scellement, ré-émission servie une fois (approuve), consommation, puis nouvel appel identique : nouveau ticket.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:10:00.000 → apr-0001 ouvert
6. voter 09:15:00.000 → apr-0001 verification
7. jeu_lu 09:15:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)
8. acquitter 09:15:02.000 → apr-0001 approuve
9. evaluer 09:16:00.000 → apr-0001 approuve
10. evaluer 09:16:00.500 → apr-0001 approuve
11. consommer 09:16:01.000 → apr-0001 consomme
12. evaluer 09:20:00.000 → apr-0001 consomme, apr-0002 reserve

### `refuse-seuil.json` (TK-3, TK-6, TK-9)

Deux votes refuse des comptes 1 et 2 : décision refuse au seuil ; la ré-émission reçoit le refus scellé ; au terme du délai de reconnaissance, clos, et la même demande ouvre un nouveau ticket.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 verification
7. jeu_lu 09:06:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : refuse (2 signatures)
8. acquitter 09:06:02.000 → apr-0001 refuse
9. evaluer 09:07:00.000 → apr-0001 refuse
10. horloge 10:06:01.900 → apr-0001 clos
11. evaluer 10:06:02.000 → apr-0001 clos, apr-0002 reserve

### `expire-sans-vote.json` (TK-3, TK-4)

Aucun vote : à l'échéance (ts de la demande + 1 h), expire ; un vote reçu à l'instant de l'échéance arrive après elle (minuteur d'abord) ; les deux escalades configurées ne changent rien.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. horloge 09:30:00.200 → apr-0001 ouvert
6. horloge 09:50:00.200 → apr-0001 ouvert
7. voter 10:00:00.200 → apr-0001 a_remettre ; refus : ticket_clos_aux_votes ; remise apr-0001/1 : expire
8. acquitter 10:00:01.000 → apr-0001 expire

### `vote-remplace.json` (TK-3, TK-5, TK-8)

Le compte 1 approuve, puis refuse (remplacement), puis refuse de nouveau avec un autre motif (vote_identique, sans effet : seule la décision compte) ; le compte 2 approuve, le compte 1 revient à approuve : la remise nomme les votes courants dans l'ordre de leur acceptation (2 puis 1) et le motif du second.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 ouvert
7. voter 09:07:00.000 → apr-0001 ouvert ; refus : vote_identique
8. voter 09:08:00.000 → apr-0001 ouvert
9. voter 09:09:00.000 → apr-0001 verification
10. jeu_lu 09:09:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `contestation-sans-objection.json` (TK-3, TK-6, TK-8)

contest_ms 900 000 (suppression de sinistre, demandeur sans adresse déclarée) : le seuil est atteint à 09:06, la fenêtre court jusqu'à 09:21 ; une approbation de plus ne la recommence pas ; à sa fin, verification, puis remise après confirmation.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 seuil_atteint
7. voter 09:10:00.000 → apr-0001 seuil_atteint
8. horloge 09:20:59.999 → apr-0001 seuil_atteint
9. horloge 09:21:00.000 → apr-0001 verification
10. jeu_lu 09:21:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `contestation-objection-levee.json` (TK-3, TK-6)

Objection du compte 3 pendant la fenêtre : retour en ouvert ; il la lève par un vote approuve : une nouvelle fenêtre complète s'ouvre (09:12 à 09:27), la première ne compte plus.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 seuil_atteint
7. voter 09:10:00.000 → apr-0001 ouvert
8. voter 09:12:00.000 → apr-0001 seuil_atteint
9. horloge 09:21:00.000 → apr-0001 seuil_atteint
10. horloge 09:27:00.000 → apr-0001 verification
11. jeu_lu 09:27:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `contestation-objection-maintenue.json` (TK-3, TK-6, TK-11)

Objection du compte 3 ; il se récuse ensuite : son vote refuse reste compté et l'objection demeure, et il ne peut plus la lever ; à l'échéance, expire, raison « objection non levee ».

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 seuil_atteint
7. voter 09:10:00.000 → apr-0001 ouvert
8. recuser 09:11:00.000 → apr-0001 ouvert
9. voter 09:12:00.000 → apr-0001 ouvert ; refus : recuse
10. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `contestation-refus-anterieur.json` (TK-3, TK-6)

contest_ms > 0 : un refus du compte 3 avant que le seuil soit atteint est une objection (EX-10.7) ; les approbations des comptes 1 et 2 n'ouvrent pas de fenêtre tant qu'elle n'est pas levée ; levée par son auteur (vote approuve), une fenêtre complète s'ouvre à cet instant.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 ouvert
7. voter 09:07:00.000 → apr-0001 ouvert
8. voter 09:10:00.000 → apr-0001 seuil_atteint
9. horloge 09:24:59.999 → apr-0001 seuil_atteint
10. horloge 09:25:00.000 → apr-0001 verification
11. jeu_lu 09:25:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `contestation-apres-echeance.json` (TK-3, TK-4, TK-6)

Seuil atteint exactement contest_ms avant l'échéance : la fenêtre finirait à l'échéance ; à instant égal, l'échéance passe d'abord : expire, raison « pendant la fenetre de contestation ».

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:40:00.200 → apr-0001 ouvert
6. voter 09:45:00.200 → apr-0001 seuil_atteint
7. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `jeu-change-pendant-contestation.json` (TK-6, TK-7)

Pendant la fenêtre de contestation (09:06 à 09:21), le compte 4 est ajouté au jeu épinglé (seuil inchangé, 2 sur 4) : nouveau gel, la fenêtre en cours est annulée et, le seuil restant atteint, une fenêtre complète s'ouvre à l'instant de la lecture (09:12 à 09:27) (EX-8.6).

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 seuil_atteint
7. jeu_lu 09:12:00.000 → apr-0001 seuil_atteint
8. horloge 09:21:00.000 → apr-0001 seuil_atteint
9. horloge 09:26:59.999 → apr-0001 seuil_atteint
10. horloge 09:27:00.000 → apr-0001 verification
11. jeu_lu 09:27:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `separation-auto-approbation.json` (TK-3, TK-11)

self_approval interdite : le vote du compte 3, adresse du demandeur, est refusé (auto_approbation) ; les comptes 1 et 2 décident.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert ; refus : auto_approbation
6. voter 09:06:00.000 → apr-0001 ouvert
7. voter 09:07:00.000 → apr-0001 verification
8. jeu_lu 09:07:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `separation-auto-permise.json` (TK-3, TK-11)

self_approval permise : le compte 3, adresse du demandeur, vote comme un autre membre ; la remise le nomme dans approvers.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 verification
7. jeu_lu 09:06:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `seuil-inatteignable.json` (TK-3, TK-6, TK-11)

Compte 3 inéligible (demandeur), compte 1 récusé : un seul éligible pour un seuil de 2 ; à l'échéance, expire, raison « seuil inatteignable ».

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. recuser 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 ouvert
7. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `recusation.json` (TK-3, TK-5, TK-11)

Récusation du compte 1 après son vote approuve : vote retiré ; récusation répétée et nouveau vote refusés (recuse) ; récusation d'un non-membre (hors_jeu) et du demandeur (auto_approbation) refusées.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. recuser 09:06:00.000 → apr-0001 ouvert
7. recuser 09:07:00.000 → apr-0001 ouvert ; refus : recuse
8. voter 09:08:00.000 → apr-0001 ouvert ; refus : recuse
9. recuser 09:09:00.000 → apr-0001 ouvert ; refus : hors_jeu
10. recuser 09:10:00.000 → apr-0001 ouvert ; refus : auto_approbation
11. voter 09:11:00.000 → apr-0001 ouvert

### `recusation-refus-maintenu.json` (TK-6, TK-11)

Demandeur sans adresse déclarée : les trois comptes sont éligibles. Le compte 1 refuse puis se récuse : son vote refuse reste compté (EX-10.4) et un nouveau vote lui est refusé (recuse) ; le refus du compte 3 complète le seuil : la remise refuse porte les signatures des comptes 1 et 3.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. recuser 09:06:00.000 → apr-0001 ouvert
7. voter 09:07:00.000 → apr-0001 ouvert ; refus : recuse
8. voter 09:08:00.000 → apr-0001 verification
9. jeu_lu 09:08:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : refuse (2 signatures)

### `jeu-change-membre-retire.json` (TK-3, TK-7, TK-8)

Pendant verification, le compte 2 est retiré du jeu 1 et le compte 4 ajouté (hauteur 1208) : nouveau gel, vote du compte 2 écarté (hors_jeu), retour en ouvert ; le compte 4 approuve ; confirmation à 1212.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 verification
7. jeu_lu 09:06:30.000 → apr-0001 ouvert
8. voter 09:08:00.000 → apr-0001 ouvert ; refus : hors_jeu
9. voter 09:09:00.000 → apr-0001 verification
10. jeu_lu 09:09:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `jeu-seuil-abaisse.json` (TK-6, TK-7, TK-8)

Pendant l'attente, l'administrateur du jeu épinglé ramène son seuil à 1 sur 3 : nouveau gel, mais le nombre de signatures exigé ne baisse pas (2, le plus grand seuil figé, EX-8.6) ; la remise porte deux signatures et le seuil lu à la confirmation, 1 sur 3 (A-3 : au moins required).

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. jeu_lu 09:06:00.000 → apr-0001 ouvert
7. voter 09:07:00.000 → apr-0001 verification
8. jeu_lu 09:07:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `jeu-reassigne.json` (TK-3, TK-7)

Pendant verification, le registre désigne le jeu 2 pour l'organisation : la lecture est illisible (jeu_non_attendu : le jeu 1 est épinglé par la politique, EX-8.1), sans nouveau gel ; une lecture lu du jeu 2 est traitée de même ; le compte 4, membre du seul jeu 2, est hors_jeu ; aucune confirmation, donc aucune remise approuve ; à l'échéance, expire, raison « jeu reassigne ».

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 verification
7. jeu_lu 09:06:30.000 → apr-0001 verification
8. voter 09:07:00.000 → apr-0001 verification ; refus : hors_jeu
9. jeu_lu 09:08:00.000 → apr-0001 verification
10. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `jeu-illisible.json` (TK-3, TK-7)

Le jeu n'est jamais figé (lectures illisibles) : votes refusés (jeu_non_fige) ; à l'échéance, expire sur le jeu de repli, lu à 1190 avant la demande, source terminée par « repli ».

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert ; refus : jeu_non_fige
6. jeu_lu 09:30:00.000 → apr-0001 ouvert
7. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `non-pret.json` (TK-3)

Jeu registre jamais lu : evaluer reçoit non_pret, même après une lecture illisible ; après une lecture réussie, la demande est servie ; une version de politique non chargée : politique_inconnue.

1. evaluer 08:58:00.000 → aucun ticket ; refus : non_pret
2. jeu_lu 08:58:30.000 → aucun ticket
3. evaluer 08:59:00.000 → aucun ticket ; refus : non_pret
4. jeu_lu 08:59:30.000 → aucun ticket
5. evaluer 09:00:00.000 → apr-0001 reserve
6. evaluer 09:00:01.000 → apr-0001 reserve ; refus : politique_inconnue

### `jeu-statique.json` (TK-3, TK-7, TK-8)

approver_set statique (comptes 1 à 3, seuil 2) : aucun jeu_lu ; la réponse nouveau porte le jeu statique ; gel à l'ouverture, confirmation acquise : la remise suit l'entrée en verification au même pas ; source « jeu statique de la politique vecteurs-ct3-1 ».

1. evaluer 09:00:00.000 → apr-0001 reserve
2. ouvrir 09:00:00.250 → apr-0001 ouvert
3. voter 09:05:00.000 → apr-0001 ouvert
4. voter 09:06:00.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)
5. acquitter 09:06:01.000 → apr-0001 approuve

### `signature-hors-jeu.json` (TK-3, TK-5, TK-8)

Votes refusés : compte 4 non membre (hors_jeu) ; signature d'un autre ticket, signature des 66 caractères « 0x… » de D_A, signature de 64 octets, v = 29 (signature_invalide). Votes acceptés après normalisation : s haut (compte 1), v ∈ {0, 1} (compte 2) ; la remise porte les formes canoniques.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert ; refus : hors_jeu
6. voter 09:06:00.000 → apr-0001 ouvert ; refus : signature_invalide
7. voter 09:07:00.000 → apr-0001 ouvert ; refus : signature_invalide
8. voter 09:08:00.000 → apr-0001 ouvert ; refus : signature_invalide
9. voter 09:09:00.000 → apr-0001 ouvert ; refus : signature_invalide
10. voter 09:10:00.000 → apr-0001 ouvert
11. voter 09:11:00.000 → apr-0001 verification
12. jeu_lu 09:11:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)

### `ordre-des-raisons-de-vote.json` (TK-5, TK-11)

Votes à deux défauts : la première raison d'EX-9.10 l'emporte. Jeu non figé et signature invalide : jeu_non_fige ; non-membre et signature invalide : signature_invalide ; adresse déclarée du demandeur hors du jeu (compte 4) : hors_jeu ; demandeur et motif trop long : auto_approbation ; récusé et motif trop long : recuse ; motif trop long et même décision que le vote courant : motif_trop_long ; puis vote identique.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. voter 09:01:00.000 → apr-0001 ouvert ; refus : jeu_non_fige
5. jeu_lu 09:02:00.000 → apr-0001 ouvert
6. voter 09:03:00.000 → apr-0001 ouvert ; refus : signature_invalide
7. voter 09:04:00.000 → apr-0001 ouvert ; refus : hors_jeu
8. voter 09:05:00.000 → apr-0001 ouvert ; refus : auto_approbation
9. recuser 09:06:00.000 → apr-0001 ouvert
10. voter 09:07:00.000 → apr-0001 ouvert ; refus : recuse
11. voter 09:08:00.000 → apr-0001 ouvert
12. voter 09:09:00.000 → apr-0001 ouvert ; refus : motif_trop_long
13. voter 09:10:00.000 → apr-0001 ouvert ; refus : vote_identique

### `reemission-en-attente.json` (TK-1, TK-2, TK-3, TK-9)

Ré-émissions : sur reserve, même ticket et nouveau ; run_id et intent hors de la clé ; un argument différent fait une autre demande ; pendant l'attente, en_attente sans événement ; ouvrir répété : l'état courant ; ouvrir d'un autre request_hash : ticket_deja_ouvert ; ticket inconnu.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:00.100 → apr-0001 reserve
4. evaluer 09:00:00.150 → apr-0001 reserve, apr-0002 reserve
5. evaluer 09:00:00.180 → apr-0001 reserve, apr-0002 reserve
6. ouvrir 09:00:00.250 → apr-0001 ouvert, apr-0002 reserve
7. evaluer 09:00:01.000 → apr-0001 ouvert, apr-0002 reserve
8. ouvrir 09:00:02.000 → apr-0001 ouvert, apr-0002 reserve
9. ouvrir 09:00:03.000 → apr-0001 ouvert, apr-0002 reserve ; refus : ticket_deja_ouvert
10. ouvrir 09:00:04.000 → apr-0001 ouvert, apr-0002 reserve ; refus : ticket_inconnu

### `retrait.json` (TK-3, TK-9)

Retrait par un tiers refusé (retrait_non_autorise) ; retrait par le demandeur : échéance avancée, expire, raison « echeance avancee par retrait » ; la ré-émission reçoit le refus scellé.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. retirer 09:05:00.000 → apr-0001 ouvert ; refus : retrait_non_autorise
6. retirer 09:06:00.000 → apr-0001 a_remettre ; remise apr-0001/1 : expire
7. acquitter 09:06:01.000 → apr-0001 expire
8. evaluer 09:07:00.000 → apr-0001 expire

### `retrait-administrateur.json` (TK-3)

Le contact administrateur de la configuration du service retire le ticket (EX-7.15) : expire, raison « echeance avancee par retrait » ; un tiers, ni demandeur ni administrateur, est refusé.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. retirer 09:05:00.000 → apr-0001 ouvert ; refus : retrait_non_autorise
6. retirer 09:06:00.000 → apr-0001 a_remettre ; remise apr-0001/1 : expire

### `acquittement-temporaire.json` (TK-3, TK-4, TK-8)

Refus temporaire du noyau (mode dégradé) puis échéance : la décision approuve, non scellée, devient caduque et une remise expire la remplace (apr-0001/2) ; un acquittement de l'ancienne remise est sans effet ; la nouvelle est scellée.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:10:00.000 → apr-0001 ouvert
6. voter 09:15:00.000 → apr-0001 verification
7. jeu_lu 09:15:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)
8. acquitter 09:15:02.000 → apr-0001 a_remettre
9. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/2 : expire
10. acquitter 10:00:01.000 → apr-0001 a_remettre
11. acquitter 10:00:02.000 → apr-0001 expire

### `deja-decide.json` (TK-3, TK-9)

Le noyau refuse une remise parce qu'une décision est déjà scellée pour cette demande (ticket_deja_decide) : le service s'aligne et garde l'objet approval scellé reçu, même s'il diffère de sa remise (ordre des signataires, motif) ; un second ticket est expiré par le noyau seul, à l'échéance plus timeout_ms (expiration) : le service s'aligne, après sa propre remise expire, et rend à la ré-émission l'objet du noyau.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:00.050 → apr-0001 reserve, apr-0002 reserve
4. ouvrir 09:00:00.250 → apr-0001 ouvert, apr-0002 reserve
5. ouvrir 09:00:00.300 → apr-0001 ouvert, apr-0002 ouvert
6. jeu_lu 09:00:01.000 → apr-0001 ouvert, apr-0002 ouvert
7. voter 09:10:00.000 → apr-0001 ouvert, apr-0002 ouvert
8. voter 09:15:00.000 → apr-0001 verification, apr-0002 ouvert
9. jeu_lu 09:15:01.000 → apr-0001 a_remettre, apr-0002 ouvert ; remise apr-0001/1 : approuve (2 signatures)
10. acquitter 09:15:02.000 → apr-0001 approuve, apr-0002 ouvert
11. evaluer 09:16:00.000 → apr-0001 approuve, apr-0002 ouvert
12. expiration 10:00:02.300 → apr-0001 approuve, apr-0002 expire ; remise apr-0002/1 : expire
13. expiration 10:00:03.000 → apr-0001 approuve, apr-0002 expire
14. evaluer 10:00:04.000 → apr-0001 approuve, apr-0002 expire

### `deja-decide-autre-demande.json` (TK-1, TK-3, TK-9)

Un service qui aurait réattribué l'identifiant apr-0001 : le noyau refuse la remise refuse par ticket_deja_decide, avec la décision scellée d'une autre demande (autre request_hash) ; le service ne s'aligne pas (T20) : ticket clos, alerte identifiant_en_collision ; la ré-émission de la demande est une nouvelle demande ; l'acquittement répété est sans effet.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:05:00.000 → apr-0001 ouvert
6. voter 09:06:00.000 → apr-0001 verification
7. jeu_lu 09:06:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : refuse (2 signatures)
8. acquitter 09:06:02.000 → apr-0001 clos
9. evaluer 09:07:00.000 → apr-0001 clos, apr-0002 reserve
10. acquitter 09:07:30.000 → apr-0001 clos, apr-0002 reserve

### `acquittements-noyau.json` (TK-3, TK-8, TK-9)

Acquittements du noyau : remise approuve refusée pour signature_invalide (T16 : votes écartés, retour en ouvert), acquittement répété sans effet ; seconde remise refusée par ticket_deja_decide avec une décision refuse (T14 : alignement sur une décision différente de la remise) ; scellement contraire refusé ; sur un second ticket, refus echeance_depassee avant l'échéance du service (T15), puis décision caduque, ancienne remise sans effet, scellement de l'expiration.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:00.050 → apr-0001 reserve, apr-0002 reserve
4. ouvrir 09:00:00.250 → apr-0001 ouvert, apr-0002 reserve
5. ouvrir 09:00:00.300 → apr-0001 ouvert, apr-0002 ouvert
6. jeu_lu 09:00:01.000 → apr-0001 ouvert, apr-0002 ouvert
7. voter 09:10:00.000 → apr-0001 ouvert, apr-0002 ouvert
8. voter 09:11:00.000 → apr-0001 verification, apr-0002 ouvert
9. jeu_lu 09:11:01.000 → apr-0001 a_remettre, apr-0002 ouvert ; remise apr-0001/1 : approuve (2 signatures)
10. acquitter 09:11:02.000 → apr-0001 ouvert, apr-0002 ouvert
11. acquitter 09:11:03.000 → apr-0001 ouvert, apr-0002 ouvert
12. voter 09:20:00.000 → apr-0001 ouvert, apr-0002 ouvert
13. voter 09:21:00.000 → apr-0001 verification, apr-0002 ouvert
14. jeu_lu 09:21:01.000 → apr-0001 a_remettre, apr-0002 ouvert ; remise apr-0001/2 : approuve (2 signatures)
15. acquitter 09:21:02.000 → apr-0001 refuse, apr-0002 ouvert
16. evaluer 09:22:00.000 → apr-0001 refuse, apr-0002 ouvert
17. acquitter 09:22:30.000 → apr-0001 refuse, apr-0002 ouvert ; refus : requete_invalide
18. voter 09:58:00.000 → apr-0001 refuse, apr-0002 ouvert
19. voter 09:59:00.000 → apr-0001 refuse, apr-0002 verification
20. jeu_lu 09:59:30.000 → apr-0001 refuse, apr-0002 a_remettre ; remise apr-0002/1 : approuve (2 signatures)
21. acquitter 09:59:59.000 → apr-0001 refuse, apr-0002 a_remettre
22. horloge 10:00:00.280 → apr-0001 refuse, apr-0002 a_remettre ; remise apr-0002/2 : expire
23. acquitter 10:00:01.000 → apr-0001 refuse, apr-0002 a_remettre
24. acquitter 10:00:02.000 → apr-0001 refuse, apr-0002 expire

### `expiration-noyau.json` (TK-3, TK-9)

Expirations scellées par le noyau seul (T17). Remise expire refusée par le noyau (T16) : pas de nouvelle remise ; le noyau scelle expire et l'annonce ; l'acquittement répété est sans effet. Expiration d'un ticket encore en reserve (horloges décalées) : request_hash inscrit, ouvrir tardif sans effet. Expiration d'un ticket abandonné : la clé n'est pas reprise.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. horloge 10:00:00.200 → apr-0001 a_remettre ; remise apr-0001/1 : expire
6. acquitter 10:00:01.000 → apr-0001 a_remettre
7. horloge 10:00:02.000 → apr-0001 a_remettre
8. expiration 10:00:02.300 → apr-0001 expire
9. acquitter 10:00:03.000 → apr-0001 expire
10. evaluer 10:00:04.000 → apr-0001 expire
11. evaluer 10:01:00.000 → apr-0001 expire, apr-0002 reserve
12. expiration 10:01:01.000 → apr-0001 expire, apr-0002 expire
13. evaluer 10:01:02.000 → apr-0001 expire, apr-0002 expire
14. ouvrir 10:01:03.000 → apr-0001 expire, apr-0002 expire
15. evaluer 10:02:00.000 → apr-0001 expire, apr-0002 expire, apr-0003 reserve
16. horloge 11:02:00.000 → apr-0001 clos, apr-0002 clos, apr-0003 abandonne
17. expiration 11:02:02.300 → apr-0001 clos, apr-0002 clos, apr-0003 expire
18. evaluer 11:02:03.000 → apr-0001 clos, apr-0002 clos, apr-0003 expire, apr-0004 reserve

### `retenir-double-reemission.json` (TK-9, TK-10)

Mode retenir : le noyau scelle la décision approuve et relaie la requête qu'il retient (acquitter scelle, held) : l'approbation est servie dès le scellement ; une ré-émission de même clé avant consommer reçoit en_attente, jamais un second autorise ; après consommer, la même demande est nouvelle (EX-7.17, EX-11.5).

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:10:00.000 → apr-0001 ouvert
6. voter 09:15:00.000 → apr-0001 verification
7. jeu_lu 09:15:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)
8. acquitter 09:15:02.000 → apr-0001 approuve
9. evaluer 09:15:30.000 → apr-0001 approuve
10. consommer 09:16:00.000 → apr-0001 consomme
11. evaluer 09:17:00.000 → apr-0001 consomme, apr-0002 reserve

### `reservation-abandonnee.json` (TK-3, TK-4)

Réservation sans ouvrir : abandonne à reserved_at + 1 h, clé libérée (la même demande ouvre apr-0002) ; ouvrir tardif d'apr-0001 : a_remettre, expire sur le jeu de repli, raison « reservation abandonnee avant l'ouverture » ; la clé n'est pas reprise.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. horloge 10:00:00.000 → apr-0001 abandonne
4. evaluer 10:00:05.000 → apr-0001 abandonne, apr-0002 reserve
5. ouvrir 10:00:10.000 → apr-0001 a_remettre, apr-0002 reserve ; remise apr-0001/1 : expire
6. acquitter 10:00:11.000 → apr-0001 expire, apr-0002 reserve
7. evaluer 10:00:12.000 → apr-0001 expire, apr-0002 reserve

### `plafond.json` (TK-3)

max_open_tickets = 2 : une troisième demande à approuver du même demandeur reçoit plafond_atteint, sans ticket ; une ré-émission reconnue reste servie ; un autre demandeur n'est pas concerné ; une sortie autorise ou refuse non plus.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:01.000 → apr-0001 reserve, apr-0002 reserve
4. evaluer 09:00:02.000 → apr-0001 reserve, apr-0002 reserve ; refus : plafond_atteint
5. evaluer 09:00:03.000 → apr-0001 reserve, apr-0002 reserve
6. evaluer 09:00:04.000 → apr-0001 reserve, apr-0002 reserve, apr-0003 reserve
7. evaluer 09:00:05.000 → apr-0001 reserve, apr-0002 reserve, apr-0003 reserve
8. evaluer 09:00:06.000 → apr-0001 reserve, apr-0002 reserve, apr-0003 reserve

### `fenetre-ouvrante.json` (TK-3, TK-13)

Deux tickets ouvrants de même portée (u.martin, sap.payments.create, IBAN A ; 10 min, 3 appels) et un ticket non ouvrant, approuvés : le non ouvrant n'ouvre rien ; le premier ouvrant ouvre une fenêtre à l'acquittement de son scellement, debut = approval.at ; le second la remplace. Trois appels couverts l'épuisent : elle est retirée (EX-5.6). Une nouvelle demande ouvre apr-0004, dont la fenêtre est retirée à sa fin.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:00.050 → apr-0001 reserve, apr-0002 reserve
4. evaluer 09:00:00.100 → apr-0001 reserve, apr-0002 reserve, apr-0003 reserve
5. ouvrir 09:00:00.250 → apr-0001 ouvert, apr-0002 reserve, apr-0003 reserve
6. ouvrir 09:00:00.300 → apr-0001 ouvert, apr-0002 ouvert, apr-0003 reserve
7. ouvrir 09:00:00.350 → apr-0001 ouvert, apr-0002 ouvert, apr-0003 ouvert
8. jeu_lu 09:00:01.000 → apr-0001 ouvert, apr-0002 ouvert, apr-0003 ouvert
9. voter 09:10:00.000 → apr-0001 ouvert, apr-0002 ouvert, apr-0003 ouvert
10. voter 09:10:01.000 → apr-0001 verification, apr-0002 ouvert, apr-0003 ouvert
11. voter 09:10:02.000 → apr-0001 verification, apr-0002 ouvert, apr-0003 ouvert
12. voter 09:10:03.000 → apr-0001 verification, apr-0002 verification, apr-0003 ouvert
13. voter 09:10:04.000 → apr-0001 verification, apr-0002 verification, apr-0003 ouvert
14. voter 09:10:05.000 → apr-0001 verification, apr-0002 verification, apr-0003 verification
15. jeu_lu 09:15:01.000 → apr-0001 a_remettre, apr-0002 a_remettre, apr-0003 a_remettre ; remise apr-0001/1 : approuve (2 signatures) ; remise apr-0002/1 : approuve (2 signatures) ; remise apr-0003/1 : approuve (2 signatures)
16. acquitter 09:15:02.000 → apr-0001 a_remettre, apr-0002 approuve, apr-0003 a_remettre
17. acquitter 09:15:03.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 a_remettre
18. acquitter 09:15:04.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve
19. evaluer 09:16:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve
20. evaluer 09:17:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve
21. evaluer 09:18:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve
22. evaluer 09:19:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 reserve
23. ouvrir 09:19:00.250 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 ouvert
24. jeu_lu 09:19:01.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 ouvert
25. voter 09:20:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 ouvert
26. voter 09:21:00.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 verification
27. jeu_lu 09:21:01.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 a_remettre ; remise apr-0004/1 : approuve (2 signatures)
28. acquitter 09:21:02.000 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 approuve
29. horloge 09:31:01.899 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 approuve
30. horloge 09:31:01.900 → apr-0001 approuve, apr-0002 approuve, apr-0003 approuve, apr-0004 approuve

### `fenetre-politique-changee.json` (TK-3, TK-13)

Deux tickets ouvrants (IBAN A et IBAN B) : le premier ouvre sa fenêtre ; un charger de la version vecteurs-ct3-2 ferme toutes les fenêtres ; le second, scellé après le changement, n'en ouvre aucune.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. evaluer 09:00:00.050 → apr-0001 reserve, apr-0002 reserve
4. ouvrir 09:00:00.250 → apr-0001 ouvert, apr-0002 reserve
5. ouvrir 09:00:00.300 → apr-0001 ouvert, apr-0002 ouvert
6. jeu_lu 09:00:01.000 → apr-0001 ouvert, apr-0002 ouvert
7. voter 09:10:00.000 → apr-0001 ouvert, apr-0002 ouvert
8. voter 09:10:01.000 → apr-0001 verification, apr-0002 ouvert
9. voter 09:10:02.000 → apr-0001 verification, apr-0002 ouvert
10. voter 09:10:03.000 → apr-0001 verification, apr-0002 verification
11. jeu_lu 09:15:01.000 → apr-0001 a_remettre, apr-0002 a_remettre ; remise apr-0001/1 : approuve (2 signatures) ; remise apr-0002/1 : approuve (2 signatures)
12. acquitter 09:15:02.000 → apr-0001 approuve, apr-0002 a_remettre
13. charger 09:16:00.000 → apr-0001 approuve, apr-0002 a_remettre
14. acquitter 09:16:01.000 → apr-0001 approuve, apr-0002 approuve

### `politique-changee.json` (TK-2, TK-3)

Après le chargement de vecteurs-ct3-2, la même demande portant code.policy_version = vecteurs-ct3-2 a une autre clé : nouvelle évaluation, nouveau ticket ; le ticket approuve de la version 1 n'est pas consommé et finit clos.

1. jeu_lu 08:59:00.000 → aucun ticket
2. evaluer 09:00:00.000 → apr-0001 reserve
3. ouvrir 09:00:00.250 → apr-0001 ouvert
4. jeu_lu 09:00:01.000 → apr-0001 ouvert
5. voter 09:10:00.000 → apr-0001 ouvert
6. voter 09:15:00.000 → apr-0001 verification
7. jeu_lu 09:15:01.000 → apr-0001 a_remettre ; remise apr-0001/1 : approuve (2 signatures)
8. acquitter 09:15:02.000 → apr-0001 approuve
9. charger 09:20:00.000 → apr-0001 approuve
10. evaluer 09:21:00.000 → apr-0001 approuve, apr-0002 reserve
11. horloge 10:15:01.900 → apr-0001 clos, apr-0002 reserve

## decisions/ (A.7, SG-1 à SG-6)

| Cas | Vérification visée | Résultat attendu | Ce qu'il exerce |
|---|---|---|---|
| `decisions/valides/approbation-2-sur-3.json` | — | scelle | Approbation des comptes 1 et 2 sur le jeu 1 (2 sur 3), écrite avant l'échéance. |
| `decisions/valides/refus-2-sur-3.json` | — | scelle | Refus des comptes 1 et 2 : mêmes règles que l'approbation (A-3). |
| `decisions/valides/expiration-sans-signature.json` | — | scelle | Expiration sans signature, écrite à l'échéance : SG-4 ne vise que approuve et refuse. |
| `decisions/valides/jeu-statique.json` | — | scelle | Approbation sur un jeu statique : source « jeu statique de la politique vecteurs-ct3-1 ». |
| `decisions/valides/ct1-apr-2201.json` | — | scelle | La décision du ticket apr-2201 des vecteurs de CT-1 (journal-sinistres, seq 6) : approval augmenté de at = l'approval de l'événement, clé pour clé (exemple de CT-3 §12.5). |
| `decisions/valides/separation-non-verifiee-par-le-noyau.json` | — | scelle | Le compte 3, adresse du demandeur, signe avec le compte 1 : le noyau scelle, il ne vérifie pas la séparation des tâches (EX-9.12). |
| `decisions/invalides/sg1-at-present.json` | SG-1 | refuse, remise_mal_formee | approval porte at, que l'écrivain pose. |
| `decisions/invalides/sg1-ticket-different.json` | SG-1 | refuse, remise_mal_formee | approval.ticket (apr-0002) différent du ticket de la remise. |
| `decisions/invalides/sg1-source-libre.json` | SG-1 | refuse, remise_mal_formee | source en texte libre, hors d'EX-8.8. |
| `decisions/invalides/sg1-signature-courte.json` | SG-1 | refuse, remise_mal_formee | Signature de 64 octets. |
| `decisions/invalides/sg2-ticket-inconnu.json` | SG-2 | refuse, ticket_inconnu | Aucun événement retenue ne porte ce ticket. |
| `decisions/invalides/sg2-request-hash-different.json` | SG-2 | refuse, request_hash_different | L'événement retenue du ticket a un autre hash. |
| `decisions/invalides/sg3-deja-decide.json` | SG-3 | refuse, ticket_deja_decide | Une décision est déjà scellée pour ce ticket. |
| `decisions/invalides/sg4-ecriture-a-l-echeance.json` | SG-4 | refuse, echeance_depassee | Écriture à l'instant exact de l'échéance (ts + 1 h) : non strictement antérieure. |
| `decisions/invalides/sg4-ecriture-apres-l-echeance.json` | SG-4 | refuse, echeance_depassee | Refus écrit après l'échéance. |
| `decisions/invalides/sg5-signature-sur-la-chaine.json` | SG-5 | refuse, signature_invalide | Le compte 2 a signé les 66 caractères « 0x… » de D_A au lieu de ses 32 octets (EX-9.7). |
| `decisions/invalides/sg5-approuve-pour-refuse.json` | SG-5 | refuse, signature_invalide | Signatures approuve présentées dans une remise refuse. |
| `decisions/invalides/sg5-autre-journal.json` | SG-5 | refuse, signature_invalide | Signatures sur A d'un autre journal (journal-sinistres de CT-1). |
| `decisions/invalides/sg5-s-haut.json` | SG-5 | refuse, signature_invalide | Signature du compte 2 à s haut : le noyau ne normalise pas. |
| `decisions/invalides/sg5-v-zero-un.json` | SG-5 | refuse, signature_invalide | Signature du compte 2 avec v ∈ {0, 1} : non canonique pour le noyau. |
| `decisions/invalides/sg5-longueurs-differentes.json` | SG-5 | refuse, signature_invalide | Deux approbateurs, une signature (E-5). |
| `decisions/invalides/sg5-ordre-inverse.json` | SG-5 | refuse, signature_invalide | signatures[i] ne correspond pas à approvers[i]. |
| `decisions/invalides/sg6-approbateur-double.json` | SG-6 | refuse, approbateur_double | Le compte 1 deux fois. |
| `decisions/invalides/sg6-approbateur-hors-jeu.json` | SG-6 | refuse, approbateur_hors_jeu | Le compte 4, non membre, signe validement. |
| `decisions/invalides/sg6-seuil-different-du-jeu.json` | SG-6 | refuse, seuil_different_du_jeu | approval.threshold 2 sur 3, jeu déclaré 3 sur 3. |
| `decisions/invalides/sg6-expire-avec-signature.json` | SG-6 | refuse, expire_avec_signatures | Expiration portant une signature valide du compte 1 sur A(expire). |
| `decisions/invalides/sg6-seuil-non-atteint.json` | SG-6 | refuse, seuil_non_atteint | Une seule approbation pour un seuil de 2. |
| `decisions/invalides/sg6-refus-seuil-non-atteint.json` | SG-6 | refuse, seuil_non_atteint | Un seul refus pour un seuil de 2 (EX-9.13). |
| `decisions/invalides/sg1-remise-id-autre-ticket.json` | SG-1 | refuse, remise_mal_formee | remise_id apr-0002/1 pour une remise du ticket apr-0001 : remise_id doit commencer par « <ticket>/ ». |
| `decisions/invalides/sg6-taille-differente-des-membres.json` | SG-6 | refuse, seuil_different_du_jeu | approval.threshold et jeu déclarés 2 sur 4, mais le jeu déclaré n'a que trois membres : size doit égaler le nombre de membres. |
| `decisions/invalides/ordre-sg1-sg2.json` | SG-1 | refuse, remise_mal_formee | SG-1 (approval porte at) et SG-2 (ticket sans événement retenue) en échec : SG-1 l'emporte. |
| `decisions/invalides/ordre-sg2-sg3.json` | SG-2 | refuse, request_hash_different | SG-2 (autre hash) et SG-3 (décision déjà scellée) en échec : SG-2 l'emporte. |
| `decisions/invalides/ordre-sg3-sg4.json` | SG-3 | refuse, ticket_deja_decide | SG-3 (décision déjà scellée) et SG-4 (écriture à l'échéance) en échec : SG-3 l'emporte. |
| `decisions/invalides/ordre-sg4-sg5.json` | SG-4 | refuse, echeance_depassee | SG-4 (écriture après l'échéance) et SG-5 (signatures inversées) en échec : SG-4 l'emporte. |
| `decisions/invalides/ordre-sg5-sg6.json` | SG-5 | refuse, signature_invalide | SG-5 (signatures inversées) et SG-6 (compte 4 hors jeu) en échec : SG-5 l'emporte. |
| `decisions/invalides/ordre-sg6-double-hors-jeu.json` | SG-6 | refuse, approbateur_double | Le compte 4, non membre, deux fois : approbateur_double précède approbateur_hors_jeu. |
| `decisions/invalides/ordre-sg6-hors-jeu-seuil.json` | SG-6 | refuse, approbateur_hors_jeu | Le compte 4 hors jeu, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : approbateur_hors_jeu précède seuil_different_du_jeu. |
| `decisions/invalides/ordre-sg6-seuil-expire.json` | SG-6 | refuse, seuil_different_du_jeu | Expiration signée par le compte 1, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : seuil_different_du_jeu précède expire_avec_signatures. |
| `decisions/invalides/ordre-sg6-seuil-non-atteint.json` | SG-6 | refuse, seuil_different_du_jeu | Une seule approbation, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : seuil_different_du_jeu précède seuil_non_atteint. |

## signatures/normalisation.json (A.8, EX-9.3)

Signatures du vote approuve d'apr-0001 (demande 1, journal-approbations) par les comptes de test ; chaque forme normalisée recouvre la même adresse que la forme d'entrée.

| Cas | Attendu |
|---|---|
| `canonique` | forme normalisée |
| `canonique-v28` | forme normalisée |
| `s-haut-v27` | forme normalisée |
| `s-haut-v28` | forme normalisée |
| `v-0` | forme normalisée |
| `v-1` | forme normalisée |
| `s-haut-v-0` | forme normalisée |
| `v-29` | refusée (signature_invalide) |
| `v-2` | refusée (signature_invalide) |
| `longueur-64` | refusée (signature_invalide) |
| `longueur-66` | refusée (signature_invalide) |
| `r-nul` | refusée (signature_invalide) |
| `r-egal-n` | refusée (signature_invalide) |
| `s-nul` | refusée (signature_invalide) |
| `s-egal-n` | refusée (signature_invalide) |
