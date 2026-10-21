# spec/ — spécifications de conception de NOORTRACE

Les neuf spécifications de la phase 1 du [plan](../docs/plan.md), leurs schémas
et leurs vecteurs de test. Chaque spécification est normative : un ingénieur
qui n'a pas participé au projet doit pouvoir implémenter le composant qu'elle
décrit, et un réviseur savoir à l'avance ce qui sera vérifié. L'[architecture
cible](../ARCHITECTURE.md) est le point de départ ; chaque spécification clôt
les décisions ouvertes qu'elle nomme.

## Spécifications

| Réf. | Document | État | Clôt |
|---|---|---|---|
| CT-1 | [Modèle d'événement et formats](CT-1-evenements-et-formats.md) | version 0.1, en revue pour la porte 1 | décisions ouvertes 1 et 5 |
| CT-2 | Enregistreur | à écrire | décisions 2 et 3 |
| CT-3 | Approbations | à écrire | décision 4 |
| CT-4 | Registre | à écrire | — |
| CT-5 | Ancrage | à écrire | — |
| CT-6 | Vérificateur | à écrire | — |
| CT-7 | Sécurité et conformité | à écrire | — |
| CT-8 | Déploiement et exploitation | à écrire | — |
| CT-9 | Plan de tests | à écrire | — |

Ordre d'écriture : CT-1, puis CT-6 et CT-2 en parallèle, puis CT-3, CT-4, CT-5,
puis CT-7, CT-8, CT-9.

## Schémas (`schemas/`)

JSON Schema draft 2020-12. Les identifiants `$id` (`https://noortrace.example/schemas/v0/…`)
servent aux références croisées entre schémas ; ils ne sont pas résolus en ligne.

| Fichier | Décrit | Référencé par |
|---|---|---|
| [`evenement-v0.schema.json`](schemas/evenement-v0.schema.json) | Un événement de journal (CT-1 §5) | `voisins`, `approbations` du schéma de dossier |
| [`manifeste-v0.schema.json`](schemas/manifeste-v0.schema.json) | Un manifeste de période (CT-1 §10) | — |
| [`dossier-v0.schema.json`](schemas/dossier-v0.schema.json) | L'index `dossier.json` d'un dossier de preuve (CT-1 §11), et dans ses `$defs` les fichiers compagnons `voisins`, `chemin`, `manifeste_sig`, `cles`, `approbations` | — |

Validation d'un fichier avec ajv (les trois schémas doivent être chargés
ensemble à cause des références croisées) :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s spec/schemas/evenement-v0.schema.json \
  -r spec/schemas/manifeste-v0.schema.json -r spec/schemas/dossier-v0.schema.json \
  -d mon-evenement.json
```

Pour un fichier compagnon, le schéma est un `$defs` du schéma de dossier
(par exemple `…/dossier.schema.json#/$defs/chemin`) ; `scripts/lib/journal.mjs`
(`validerSchema`) charge les trois schémas et le vérificateur de dossier
choisit la définition par fichier.

## Vecteurs de test (`vecteurs/`)

Publiés avec CT-1 sous [`vecteurs/ct-1/`](vecteurs/ct-1/INDEX.md), produits par
`scripts/vecteurs/generer-ct1.mjs` (`npm run vecteurs:ct1`) et rejoués par
`test/journal.test.js` ; tout est déterministe (clés dérivées d'une graine
documentée, horodatages et nonces fixes, comptes Hardhat 1 à 3 comme
approbateurs). Disposition, fixée par CT-1 §13 :

| Répertoire ou fichier | Contenu | Résultat attendu |
|---|---|---|
| `ct-1/cles/` | Clés de test (graines, clés publiques, comptes d'approbateurs, nonces) et `cles.json` des dossiers | égalité des dérivations |
| `ct-1/jcs/cas-limites.json` | Cas limites de la forme canonique (CT-1 §4) : entrée, forme canonique ou `null` si invalide | égalité octet par octet, ou refus |
| `ct-1/journal-valide/` | Douze événements d'un journal fictif, hachages, signatures, pièces | chaîne valide, égalité |
| `ct-1/journal-{supprime,modifie,insere,insere-sans-cle,reordonne}/` | Le même journal altéré | contrôles de la table 7.2 et diagnostics nommés |
| `ct-1/merkle/arbres.json` | Arbres de 0, 1, 2, 3, 5, 8, 12 et 1000 feuilles : racine, preuves d'inclusion | égalité, preuves acceptées |
| `ct-1/manifestes/` | Trois périodes consécutives (dont une vide), `periodHash`, signatures, `anchorFingerprint`, `PeriodMeta`, continuité, un manifeste discontinu | égalité, P-5 |
| `ct-1/dossiers/` | Deux dossiers valides et au moins un dossier invalide par contrôle de CT-1 §11.4 (§11.5) | `valide` ou liste exacte des contrôles en échec |
| `ct-1/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, qui recalcule et confronte toutes ces valeurs | zéro discordance (`go run . ..`) |

L'exemple numérique complet de CT-1 (sections 5.5, 6.4, 9.4, 10, 11 et annexes)
emploie un journal distinct (`journal-principal`) de celui des vecteurs
(`journal-sinistres`) ; il est rejoué par les tests des deux implémentations.
Un script de validation des fichiers contre les schémas est fourni avec le
vérificateur de dossier : `node scripts/verify/dossier.mjs <répertoire>`.
