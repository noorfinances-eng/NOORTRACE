# spec/ — spécifications de conception de NOORTRACE

Les neuf spécifications de la phase 1 du plan de projet (document interne),
leurs schémas
et leurs vecteurs de test. Chaque spécification est normative : un ingénieur
qui n'a pas participé au projet doit pouvoir implémenter le composant qu'elle
décrit, et un réviseur savoir à l'avance ce qui sera vérifié. L'[architecture
cible](../ARCHITECTURE.md) est le point de départ ; chaque spécification clôt
les décisions ouvertes qu'elle nomme.

## Spécifications

| Réf. | Document | État | Clôt |
|---|---|---|---|
| CT-1 | [Modèle d'événement et formats](CT-1-evenements-et-formats.md) | version 0.2, en revue pour la porte 1 | décisions ouvertes 1 et 5 |
| CT-2 | [Enregistreur](CT-2-enregistreur.md) | version 0.2, en revue pour la porte 1 | décisions 2 et 3 |
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
| [`politique-redaction-v0.schema.json`](schemas/politique-redaction-v0.schema.json) | Une politique de rédaction avant hachage (CT-2 §10) ; l'exemple complet `pii-v1` est imprimé en CT-2 §10.9 | `policy.redaction` du schéma de configuration |
| [`configuration-enregistreur-v0.schema.json`](schemas/configuration-enregistreur-v0.schema.json) | Le document unique de configuration de l'enregistreur (CT-2 §15), dont l'ensemble de politique `policy` ; l'exemple complet est imprimé en CT-2 §15.3 | — |

Validation d'un fichier avec ajv (les trois schémas doivent être chargés
ensemble à cause des références croisées) :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s spec/schemas/evenement-v0.schema.json \
  -r spec/schemas/manifeste-v0.schema.json -r spec/schemas/dossier-v0.schema.json \
  -d mon-evenement.json
```

Les deux schémas de CT-2 se chargent ensemble (la configuration référence la
politique de rédaction par son `$id`) :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --all-errors \
  -s spec/schemas/configuration-enregistreur-v0.schema.json \
  -r spec/schemas/politique-redaction-v0.schema.json \
  -d ma-configuration.json
```

Pour un fichier compagnon, le schéma est un `$defs` du schéma de dossier
(par exemple `…/dossier.schema.json#/$defs/chemin`) ; `scripts/lib/journal.mjs`
(`validerSchema`) charge les trois schémas et le vérificateur de dossier
choisit la définition par fichier.

## Vecteurs de test (`vecteurs/`)

### CT-1 (`vecteurs/ct-1/`)

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

### CT-2 (`vecteurs/ct-2/`)

Publiés avec CT-2 sous [`vecteurs/ct-2/`](vecteurs/ct-2/INDEX.md), produits par
`scripts/vecteurs/generer-ct2.mjs` (`npm run vecteurs:ct2`), rejoués par
`test/enregistreur.test.js` et confrontés par le vérificateur Go indépendant du
module séparé `vecteurs/ct-2/verificateur-independant/` (`noortrace-ct2`) ; tout
est déterministe (clés de test de CT-1, horodatages et identifiants fixes, clé
de pseudonymisation de test publique). Disposition fixée par l'annexe B de
[CT-2](CT-2-enregistreur.md) ; l'index généré `vecteurs/ct-2/INDEX.md` liste
chaque cas et son attendu. Les vecteurs CT-1 et le module Go de `ct-1` ne
changent pas.

| Répertoire | Contenu (CT-2, annexe B) | Résultat attendu |
|---|---|---|
| `ct-2/jcs-integral/` | Forme canonique **JCS intégral** des pièces (RFC 8785 tel quel, nombres compris) : table de la RFC, cas limites, pertes au-delà de 2^53 | égalité octet par octet, ou refus |
| `ct-2/redaction/` | Politique `pii-v1`, politique de pseudonymisation de test et politique de règles de test (pointeurs, `champ`, `supprimer`, motif nommé, passages successifs), motifs admis et refusés du sous-ensemble commun ECMAScript/RE2, entrées et pièces rédigées attendues (`sha256`, `length`, `redacted`, correspondances comptées) | égalité |
| `ct-2/pieces-mcp/` | Requêtes `tools/call` reçues après la liste servie (`tools/list`), relayées ou refusées au pas 1 → pièces « arguments », « résultat », « définition d'outil », « liste annoncée », `context` ; erreurs JSON-RPC et de l'enregistreur ; blancs, CR, nombres non représentables ; agrégation et nommage `alias__nom` | égalité, erreurs rendues attendues |
| `ct-2/pieces-modele/` | API Messages d'Anthropic (hors flux, flux SSE), OpenAI Chat Completions (hors flux, flux), OpenAI Responses (flux) → forme consolidée → pièce ; réponse non JSON, requête non analysable refusée, prompt laissé en place ; `code.model`, `intent`, `prompt_version` attendus | égalité |
| `ct-2/evenements/journal-demo/` | La courte exécution de la démonstration de référence (politique, échanges de modèle, lecture, écriture approuvée), chaînée avec les clés de test de CT-1, avec son segment, son journal d'intention, son ensemble de politique, ses entrées brutes (`entrees.json` : échanges, appels, liste servie, connexion d'hôte) et le dossier CT-1 de l'appel d'écriture (`dossier-seq-7/`) | chaîne valide par les outils de CT-1, égalité ; dossier valide (`node scripts/verify/dossier.mjs`, code 0) |
| `ct-2/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, module séparé de celui de `ct-1`, qui recalcule et confronte toutes ces valeurs | zéro discordance (`go run . ..`) |
