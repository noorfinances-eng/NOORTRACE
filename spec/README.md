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
| CT-1 | [Modèle d'événement et formats](CT-1-evenements-et-formats.md) | version 0.3 (révision 0.3 : point de contrôle, preuve de cohérence, partie facultative `points-de-controle.json`), en revue pour la porte 1 | décisions ouvertes 1 et 5 |
| CT-2 | [Enregistreur](CT-2-enregistreur.md) | version 0.5 (révision 0.5 : API Gemini à la passerelle, SDK Python et TypeScript, adaptateurs de cadres, ingestion OpenTelemetry, gel juridique des copies WORM, coût par agent ; révision 0.4 : production des points de contrôle), en revue pour la porte 1 | décisions 2 et 3 |
| CT-3 | [Approbations](CT-3-approbations.md) | version 0.2, en revue pour la porte 1 | décision 4 |
| CT-4 | [Registre](CT-4-registre.md) | version 0.3 (révision 0.3 minimale : libellé de `docType` du point de contrôle, §6.4 ; corrections de la revue appliquées en 0.2), en revue pour la porte 1 | — (touche les décisions 6 et 7 sans les clore, CT-4 §13) |
| CT-5 | [Ancrage](CT-5-ancrage.md) | version 0.2 (révision 0.2 : corrections de la revue de la version 0.1), en revue pour la porte 1 | — (met en œuvre les points 2 et 3 de la section « Ancrage » de l'architecture et fixe la cadence des ancres des points de contrôle) |
| CT-6 | [Vérificateur](CT-6-verificateur.md) | version 0.2 (révision 0.2 : vérification de la partie `points-de-controle.json`), en revue pour la porte 1 | — |
| CT-7 | Sécurité et conformité | à écrire | — |
| CT-8 | Déploiement et exploitation | à écrire | — |
| CT-9 | Plan de tests | à écrire | — |

Ordre d'écriture : CT-1, puis CT-6 et CT-2 en parallèle, puis CT-3, CT-4, CT-5,
puis CT-7, CT-8, CT-9.

## Schémas (`schemas/`)

JSON Schema draft 2020-12. Les identifiants `$id`
(`https://noortrace.example/schemas/v0/…`) servent aux références croisées entre
schémas ; ils ne sont pas résolus en ligne.

| Fichier | Décrit | Référencé par |
|---|---|---|
| [`evenement-v0.schema.json`](schemas/evenement-v0.schema.json) | Un événement de journal (CT-1 §5) | `voisins`, `approbations` du schéma de dossier |
| [`manifeste-v0.schema.json`](schemas/manifeste-v0.schema.json) | Un manifeste de période (CT-1 §10) | — |
| [`dossier-v0.schema.json`](schemas/dossier-v0.schema.json) | L'index `dossier.json` d'un dossier de preuve (CT-1 §11 ; douze parties, ou treize avec `points_de_controle` depuis CT-1 révision 0.3), et dans ses `$defs` les fichiers compagnons `voisins`, `chemin`, `manifeste_sig`, `cles`, `approbations` et la partie facultative `points_de_controle` (`preuve_coherence`, ancres embarquées) ; il référence le schéma du point par son `$id` | — |
| [`point-de-controle-v0.schema.json`](schemas/point-de-controle-v0.schema.json) | Un point de contrôle de la période en cours (CT-1 §10.5, révision 0.3) ; l'exemple complet est imprimé en CT-1 §10.5 | `checkpoint` de `$defs/points_de_controle` du schéma de dossier |
| [`politique-redaction-v0.schema.json`](schemas/politique-redaction-v0.schema.json) | Une politique de rédaction avant hachage (CT-2 §10) ; l'exemple complet `pii-v1` est imprimé en CT-2 §10.9 | `policy.redaction` du schéma de configuration |
| [`configuration-enregistreur-v0.schema.json`](schemas/configuration-enregistreur-v0.schema.json) | Le document unique de configuration de l'enregistreur (CT-2 §15), dont l'ensemble de politique `policy` ; l'exemple complet est imprimé en CT-2 §15.3 ; il référence les schémas de politique de rédaction et de politique d'approbation ; depuis CT-2 révision 0.5, ajouts compatibles : `$defs/model_route` (route `gemini`), `otel`, `policy.otel`, `policy.sdk` et `$defs/worm` | — |
| [`worm-v0.schema.json`](schemas/worm-v0.schema.json) | Gel juridique et contrôle des copies WORM (CT-2 §12.6 et §12.11, révision 0.5) : ligne du registre des copies, ligne de la liste des objets d'un gel, enregistrement du registre des gels, et dans ses `$defs` les fichiers de cas de la famille `ct-2/worm/` | — |
| [`cout-agent-v0.schema.json`](schemas/cout-agent-v0.schema.json) | Entrées et sorties de la formule du coût annuel par agent (CT-2 §16.4, révision 0.5), prix en unités symboliques, et le fichier de cas de la famille `ct-2/cout-agent/` | — |
| [`rapport-verification-v0.schema.json`](schemas/rapport-verification-v0.schema.json) | La sortie JSON du vérificateur (`--json`) : rapport (codes 0, 1, 3) ou rapport d'erreur (code 2) (CT-6 §8.6) | — |
| [`ancres-confiance-v0.schema.json`](schemas/ancres-confiance-v0.schema.json) | Le fichier d'ancres de confiance écrit par le réviseur (CT-6 §12) ; l'exemple complet est imprimé en CT-6 §12.3 | — |
| [`entetes-bitcoin-v0.schema.json`](schemas/entetes-bitcoin-v0.schema.json) | La chaîne d'en-têtes Bitcoin fournie à part (`--entetes-bitcoin`, CT-6 §10.3) | — |
| [`registre-v0.schema.json`](schemas/registre-v0.schema.json) | La partie `registre.json` du dossier (CT-6 §11.2.1), et dans ses `$defs` la partie `certificat-commit.json` (`certificat_commit`, §11.2.2) | — |
| [`validateurs-v0.schema.json`](schemas/validateurs-v0.schema.json) | La partie `validateurs.json` du dossier (CT-6 §11.2.3) | — |
| [`politique-approbation-v0.schema.json`](schemas/politique-approbation-v0.schema.json) | La politique d'approbation, membre `/policy/approval/rules` de l'ensemble de politique (CT-3 §4) ; l'exemple complet est imprimé en CT-3 §4.3 | `policy.approval.rules` du schéma de configuration (CT-2 §15) ; `jeu_approbateurs` et `separation`, repris par le schéma de ticket |
| [`ticket-v0.schema.json`](schemas/ticket-v0.schema.json) | La trace d'un ticket que le service d'approbation persiste (CT-3 §7), et dans ses `$defs` le jeu d'approbateurs figé (§8), la fenêtre ouverte (§5.3), la remise d'une décision au noyau (`remise`, §12.5) et les formats des vecteurs de CT-3 (annexe A) | — |
| [`instance-registre-v0.schema.json`](schemas/instance-registre-v0.schema.json) | Le manifeste d'une instance du registre que l'exploitant publie : genèse, identifiants, version de noorcore, jeux de validateurs, frais, contrats et comptes (CT-4 §4.8) ; l'exemple du réseau de développement est imprimé en CT-4 §4.8 | — |
| [`inscription-client-v0.schema.json`](schemas/inscription-client-v0.schema.json) | Le dossier d'inscription d'un client au registre, demande et état de chaque étape (CT-4 §7) ; l'exemple complet est imprimé en CT-4 §7.10 | — |
| [`operations-registre-v0.schema.json`](schemas/operations-registre-v0.schema.json) | L'index de capture d'une transaction du registre (CT-4 §9.4), et dans ses `$defs` la demande de signature (`demande_signature`, §7.7), l'envoi d'une transaction (`envoi`), la sortie des outils de référence (`sortie`, §7.2) et les formats des vecteurs de CT-4 (annexe A) | — |
| [`ancrage-v0.schema.json`](schemas/ancrage-v0.schema.json) | Le document unique de configuration de l'ancrage (CT-5 §4.4) : prestataires RFC 3161 et leur statut qualifié mesurable, cadences, fraîcheur, reprise, registre, OpenTimestamps, file ; l'exemple complet est imprimé en CT-5 §4.4 | — |
| [`planificateur-ancrage-v0.schema.json`](schemas/planificateur-ancrage-v0.schema.json) | Une trace normative du planificateur d'ancrage (CT-5 §8.10 : projection de la configuration, entrées, actions attendues, file finale), et dans ses `$defs` une demande de la file (`demande`), les cas de coût et de requête et le fichier de famille des vecteurs de CT-5 (annexe A) ; la trace de référence est imprimée en CT-5 §8.10 | — |

Validation d'un fichier avec ajv (les quatre schémas de CT-1 doivent être
chargés ensemble à cause des références croisées ; depuis CT-1 révision 0.3,
le schéma de dossier référence celui du point de contrôle) :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s spec/schemas/evenement-v0.schema.json \
  -r spec/schemas/manifeste-v0.schema.json -r spec/schemas/dossier-v0.schema.json \
  -r spec/schemas/point-de-controle-v0.schema.json \
  -d mon-evenement.json
```

Le schéma de configuration de CT-2 se charge avec ceux des deux politiques,
qu'il référence par leur `$id` (rédaction, CT-2 §10 ; approbation, CT-3 §4) :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --all-errors \
  -s spec/schemas/configuration-enregistreur-v0.schema.json \
  -r spec/schemas/politique-redaction-v0.schema.json \
  -r spec/schemas/politique-approbation-v0.schema.json \
  -d ma-configuration.json
```

Les schémas `worm-v0` et `cout-agent-v0` de CT-2 (révision 0.5) n'ont aucune
référence croisée ; une définition de leurs `$defs` se valide par un schéma
d'appel, comme ci-dessous pour un enregistrement du registre des gels :

```bash
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/worm.schema.json#/$defs/enregistrement_gel"}' > enregistrement-gel.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s enregistrement-gel.schema.json -r spec/schemas/worm-v0.schema.json \
  -d 0001-pose.json
```

Les cinq schémas de CT-6 n'ont aucune référence croisée et se compilent en
mode strict. Le réviseur valide son fichier d'ancres ainsi :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/ancres-confiance-v0.schema.json -d mes-ancres.json
```

`certificat-commit.json` se valide par un schéma enveloppe qui désigne
`$defs/certificat_commit` du schéma de registre :

```bash
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/registre.schema.json#/$defs/certificat_commit"}' > certificat-commit.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s certificat-commit.schema.json -r spec/schemas/registre-v0.schema.json \
  -d certificat-commit.json
```

Les deux schémas de CT-3 se compilent en mode strict. Une politique
d'approbation se valide seule contre son schéma (la partie « schéma » de CT-3
EX-4.2 ; les règles que le schéma n'exprime pas relèvent du service) ; le
schéma de ticket se charge avec celui de l'événement et celui de la politique,
et un format de ses `$defs` (une remise, un fichier de vecteurs) se valide par
un schéma enveloppe :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/politique-approbation-v0.schema.json -d politique-approbation.json
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/ticket.schema.json#/$defs/remise"}' > remise.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s remise.schema.json -r spec/schemas/ticket-v0.schema.json \
  -r spec/schemas/evenement-v0.schema.json -r spec/schemas/politique-approbation-v0.schema.json \
  -d remise.json
```

Pour un fichier compagnon, le schéma est un `$defs` du schéma de dossier
(par exemple `…/dossier.schema.json#/$defs/chemin`, ou
`#/$defs/points_de_controle` pour la partie facultative de CT-1 révision 0.3) ;
`scripts/lib/journal.mjs` (`validerSchema`) charge les quatre schémas et le
vérificateur de dossier choisit la définition par fichier.

Les deux schémas de CT-5 n'ont aucune référence croisée et se compilent en
mode strict. Une configuration d'ancrage se valide seule ; une trace du
planificateur se valide contre la racine de `planificateur-ancrage-v0`, et
une demande de la file ou un fichier de famille des vecteurs par un schéma
enveloppe qui désigne `#/$defs/demande` ou `#/$defs/fichier_vecteurs` :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/ancrage-v0.schema.json -d ma-configuration-ancrage.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/planificateur-ancrage-v0.schema.json -d ma-trace.json
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/planificateur-ancrage.schema.json#/$defs/demande"}' > demande.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s demande.schema.json -r spec/schemas/planificateur-ancrage-v0.schema.json -d ma-demande.json
```

Les trois schémas de CT-4 n'ont aucune référence croisée et se compilent en
mode strict. Le manifeste d'instance, le dossier d'inscription et l'index de
capture se valident seuls contre leur schéma ; un format des `$defs`
d'`operations-registre-v0` (une demande de signature, une sortie d'outil) se
valide par un schéma enveloppe :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s spec/schemas/instance-registre-v0.schema.json -d instance-r1.json
echo '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://noortrace.example/schemas/v0/operations-registre.schema.json#/$defs/demande_signature"}' > demande-signature.schema.json
npx --yes ajv-cli@5 validate --spec=draft2020 --strict=true \
  -s demande-signature.schema.json -r spec/schemas/operations-registre-v0.schema.json \
  -d demande-inscription.json
```

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
| `ct-1/points-de-controle/`, `ct-1/merkle/coherence.json` (révision 0.3) | Séries complètes des points des trois périodes (`checkpointHash`, signatures, chaînage, preuves de cohérence vers chaque manifeste) et séries invalides nommées par règle ; preuves de cohérence entre les arbres publiés et cas refusés ; dix dossiers de la révision 0.3 (neuf portent la partie `points-de-controle.json`, un la déclare absente ; CT-1 §11.5, §13), dont le point de clôture et le double défaut de K-1 | égalité, acceptation, refus ; les quarante dossiers existants inchangés ; confrontés à `transparency-dev/merkle` v0.0.2 (`vecteurs/ct-5/confrontation/coherence/`) |
| `ct-1/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, qui recalcule et confronte toutes ces valeurs | zéro discordance (`go run . ..`) |

L'exemple numérique complet de CT-1 (sections 5.5, 6.4, 9.4, 10, 11 et annexes)
emploie un journal distinct (`journal-principal`) de celui des vecteurs
(`journal-sinistres`) ; il est rejoué par les tests des deux implémentations.
Un script de validation des fichiers contre les schémas est fourni avec le
vérificateur de dossier : `node scripts/verify/dossier.mjs <répertoire>`.

### CT-2 (`vecteurs/ct-2/`)

Publiés avec CT-2 sous [`vecteurs/ct-2/`](vecteurs/ct-2/INDEX.md), produits par
`scripts/vecteurs/generer-ct2.mjs` (`npm run vecteurs:ct2`), rejoués par
`test/enregistreur.test.js` (et, pour la révision 0.5, par
`test/enregistreur-r05.test.js`) et confrontés par le vérificateur Go
indépendant du module séparé `vecteurs/ct-2/verificateur-independant/`
(`noortrace-ct2`) ; tout est déterministe (clés de test de CT-1, horodatages et
identifiants fixes, clé de pseudonymisation de test publique). Disposition fixée
par l'annexe B de [CT-2](CT-2-enregistreur.md) ; l'index généré
`vecteurs/ct-2/INDEX.md` liste chaque cas et son attendu. Les vecteurs CT-1 et
le module Go de `ct-1` ne changent pas.

| Répertoire | Contenu (CT-2, annexe B) | Résultat attendu |
|---|---|---|
| `ct-2/jcs-integral/` | Forme canonique **JCS intégral** des pièces (RFC 8785 tel quel, nombres compris) : table de la RFC, cas limites, pertes au-delà de 2^53 | égalité octet par octet, ou refus |
| `ct-2/redaction/` | Politique `pii-v1`, politique de pseudonymisation de test et politique de règles de test (pointeurs, `champ`, `supprimer`, motif nommé, passages successifs), motifs admis et refusés du sous-ensemble commun ECMAScript/RE2 et de ses règles de structure et de taille (formes à retour arrière exponentiel et quantificateurs à zéro non significatif refusés ; motifs à « (?P< » avec leur première correspondance), entrées et pièces rédigées attendues (`sha256`, `length`, `redacted`, correspondances comptées) | égalité |
| `ct-2/pieces-mcp/` | Requêtes `tools/call` reçues après la liste servie (`tools/list`), relayées ou refusées au pas 1 → pièces « arguments », « résultat », « définition d'outil », « liste annoncée », `context` ; erreurs JSON-RPC et de l'enregistreur (codes `-31010` à `-31017`) ; refus par la politique et signal d'approbation, résultats `isError` rendus par l'enregistreur ; blancs, CR, nombres non représentables ; agrégation et nommage `alias__nom` | égalité, erreurs et résultats rendus attendus |
| `ct-2/pieces-modele/` | API Messages d'Anthropic (hors flux, flux SSE), OpenAI Chat Completions (hors flux, flux), OpenAI Responses (flux) → forme consolidée → pièce ; réponse non JSON, requête non analysable refusée, prompt laissé en place ; `code.model`, `intent`, `prompt_version` attendus ; depuis la révision 0.5, cas `gemini-*` (`generateContent`, `streamGenerateContent`, refus de la passerelle, `echangeModele` du SDK au format `gemini`) | égalité ; requêtes et réponses Gemini confrontées aux types de `google-genai` 2.33.0 (`vecteurs/ct-2/confrontation/gemini/`) |
| `ct-2/otel/` (révision 0.5) | Requêtes OTLP/HTTP en JSON et en protobuf reçues d'une source OpenTelemetry → forme normalisée des spans, classement, doublons et recouvrements, pièces, événements et réponses OTLP ; refus (`400`, `401`, `404`, `413`, `415`) | égalité ; requêtes confrontées à `opentelemetry-proto` 1.45.1 (`vecteurs/ct-2/confrontation/otel/`), divergences voulues publiées |
| `ct-2/worm/` (révision 0.5) | Requêtes exactes de gel, de lecture et de rétention par support (S3, Azure, GCS), verdict du verrou d'une version, périmètre d'un gel, règle de garde de la levée par deux personnes, versions à lever quand d'autres gels actifs les couvrent | égalité |
| `ct-2/cout-agent/` (révision 0.5) | Formule du coût annuel par agent : neuf cas, prix en unités symboliques, jamais un prix réel | égalité |
| `ct-2/evenements/journal-demo/` | La courte exécution de la démonstration de référence (politique, échanges de modèle, lecture, écriture approuvée), chaînée avec les clés de test de CT-1, avec son segment, son journal d'intention, son ensemble de politique, ses entrées brutes (`entrees.json` : échanges, appels, liste servie, connexion d'hôte) et le dossier CT-1 de l'appel d'écriture (`dossier-seq-7/`) | chaîne valide par les outils de CT-1, égalité ; dossier valide (`node scripts/verify/dossier.mjs`, code 0) |
| `ct-2/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, module séparé de celui de `ct-1`, qui recalcule et confronte toutes ces valeurs | zéro discordance (`go run . ..`) |
| `ct-2/confrontation/` (révision 0.5) | Programmes et sorties publiées (`sorties/`) des implémentations tierces : `google-genai` 2.33.0 (`gemini/`) et `opentelemetry-proto` 1.45.1 avec `protobuf` 7.36.2 (`otel/`), versions épinglées dans leurs `exigences.txt` ; divergences voulues déclarées (annexes B.5 et B.8) | concordance ; `test/confrontation.test.js` relie les sorties publiées aux vecteurs |

### CT-3 (`vecteurs/ct-3/`)

Disposition fixée par l'annexe A de [CT-3](CT-3-approbations.md) (A.3,
EX-A.1 à EX-A.11) : produits par `scripts/vecteurs/generer-ct3.mjs`
(`npm run vecteurs:ct3`), rejoués à l'identique par
`test/approbation.test.js` avec l'implémentation de référence
`scripts/lib/approbation.mjs`, et confrontés par le vérificateur Go
indépendant du module séparé `vecteurs/ct-3/verificateur-independant/`
(`noortrace-ct3`) ; tout est déterministe (comptes Hardhat 1 à 4, adresses
de registre, de jeu et de bloc synthétiques dérivées par SHA-256, horodatages
fixes, CT-3 A.2). L'index généré `vecteurs/ct-3/INDEX.md` liste chaque cas et
son attendu. Les vecteurs de CT-1, CT-2 et CT-6 ne changent pas.

| Répertoire ou fichier | Contenu (CT-3, annexe A) | Résultat attendu |
|---|---|---|
| `ct-3/politiques/`, `ct-3/politiques-invalides/` | Politiques `politique-approbation-v0` valides, et refusées avec leur `attendu.json` (A.4) | validation, liste complète des erreurs (AP-1 à AP-4) |
| `ct-3/evaluation/`, `ct-3/candidats/` | Demandes évaluées par politique, avec l'état des fenêtres ; outils susceptibles d'approbation (A.4) | `rule`, `decision`, `contest_ms`, ouverture et fenêtres (AP-5 à AP-17) |
| `ct-3/acceptation/` et `ct-3/acceptation-attendu.json` | L'épreuve des trois relecteurs : une politique, dix demandes ; les décisions attendues dans un fichier à part, que les relecteurs ne reçoivent pas (A.5) | mêmes décisions pour les trois relecteurs et l'attendu |
| `ct-3/tickets/` | Traces de cycle de vie, entrée par entrée (A.6) | état de chaque ticket, réponses, remises, fenêtres (TK-1 à TK-13) |
| `ct-3/decisions/` | Remises valides et invalides, dont la décision `apr-2201` des vecteurs de CT-1 (A.7) | `scelle`, ou refus avec la raison de la première vérification SG- en échec |
| `ct-3/signatures/normalisation.json` | Formes de signature à normaliser ou à refuser (A.8) | forme normalisée, même adresse recouvrée |
| `ct-3/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, module séparé de ceux de `ct-1` et `ct-2` | zéro discordance (`go run . ..`) |

### CT-4 (`vecteurs/ct-4/`)

Disposition fixée par l'annexe A de [CT-4](CT-4-registre.md) (A.3, EX-A.1 à
EX-A.8) : produits par `scripts/vecteurs/generer-ct4.mjs`
(`npm run vecteurs:ct4`), rejoués à l'identique par `test/registreCt4.test.js`
et confrontés par le vérificateur Go indépendant du module séparé
`vecteurs/ct-4/verificateur-independant/` (`noortrace-ct4`) ; tout est
déterministe (identifiants 2124 et `noortrace-2124-dev`, contrats et jeu de
validateurs du réseau de développement, comptes Hardhat 0 à 3, clés de chaîne,
de validateurs d'essai et d'exemple dérivées par SHA-256, signatures RFC 6979,
CT-4 A.2). Ses entrées, lues et jamais réécrites, sont les manifestes et les
clés de CT-1, la capture du registre de CT-6,
`test/fixtures/certificat-commit/validators.json` et
`chain/config/alloc-dev.json`. Les vecteurs de CT-1, CT-2, CT-3 et CT-6 ne
changent pas.

| Répertoire ou fichier | Contenu (CT-4, annexe A) | Résultat attendu |
|---|---|---|
| `ct-4/identifiants.json`, `ct-4/doctypes.json` | Slugs, noms de journal et libellés de `docType`, admis et refusés | `org_id`, `journal_id`, `docType`, ou refus (RG-1 à RG-3) |
| `ct-4/empreintes.json` | Empreintes d'ancre des trois manifestes de CT-1, période vide, cas synthétiques | égalité avec `anchor_fingerprint` de CT-1 (RG-4) |
| `ct-4/condenses.json` | Champs de clôture, six condensés internes, hachage signé, signatures et leur ordre, signatures refusées | préimages, condensés, verdicts RG-5 à RG-13 |
| `ct-4/appels.json`, `ct-4/transactions.json` | Données d'appel et transactions de type 2 signées, dont celles de la capture de CT-6 | octets et hachages ; RG-14, RG-15 (`echoue` sur les frais des transactions de la capture) |
| `ct-4/manifestes/` | Manifestes d'instance valides et refusés, avec leur genèse, leur jeu et leurs index de capture | verdicts RG-16 à RG-20, ancre `registry` dérivée |
| `ct-4/demandes/`, `ct-4/inscription/` | Demandes de signature et dossiers d'inscription, valides et refusés | conformité au schéma, OP-4, OP-6, OP-7 |
| `ct-4/capture/` | Les quatre transactions de la période 1 de la capture de CT-6, et des variantes altérées | statuts CP-2 à CP-6 ; parties exportées égales à celles de `ct-6/registre/periode-1/` |
| `ct-4/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, module séparé de ceux de `ct-1`, `ct-2` et `ct-3` | zéro discordance (`go run . ..`) |

### CT-5 (`vecteurs/ct-5/`)

Disposition fixée par l'annexe A de [CT-5](CT-5-ancrage.md) (A.1 à A.8,
EX-A.1 à EX-A.7) : produits par `scripts/vecteurs/generer-ct5.mjs`
(`npm run vecteurs:ct5`), rejoués à l'identique par `test/ancrage.test.js`
avec l'implémentation de référence `scripts/lib/ancrage.mjs`, confrontés par
le vérificateur Go indépendant du module séparé
`vecteurs/ct-5/verificateur-independant/` (`noortrace-ct5`) et par OpenSSL
(`openssl ts -query`, `openssl ts -verify`) et `python-opentimestamps`
(resérialisation identique) ; tout est déterministe (nonces, gigues,
identifiants de corrélation et instants dérivés d'étiquettes, CT-5 A.2 ;
constantes dans `constantes.json`). Le générateur, le module Go, les tests et
la confrontation (`vecteurs/ct-5/confrontation/`, sorties publiées) sont en
place (CT-5 §14) ; les vecteurs de CT-2, CT-3 et CT-4 ne changent pas, ceux de
CT-1 (révision 0.3) et de CT-6 (révision 0.2) s'étendent sans modifier un
fichier existant.

| Répertoire ou fichier | Contenu (CT-5, annexe A) | Résultat attendu |
|---|---|---|
| `ct-5/requetes/` | Requêtes `TimeStampReq` DER construites octet pour octet (CT-5 EX-5.1 : SHA-256 à `NULL` explicite, nonce de 64 bits dérivé d'une étiquette, `reqPolicy` facultatif, `certReq` vrai), dont `requete-point-k2.tsq` à laquelle le jeton de CT-1 §11.2 répond ; cas refusés par le constructeur (AN-5, AN-6) | octets exacts ; `openssl ts -query -in -text` |
| `ct-5/reponses/` | Réponses `TimeStampResp` de l'autorité de test de CT-6 et jetons extraits, valides et invalides (nonce différent ou absent, autre empreinte, politique refusée, rejets `unacceptedPolicy` et `badAlg`, statuts 3 et 5, signature altérée, réponses HTTP représentées, réponses tardives, `genTime` hors tolérance) | issue d'EX-5.13, code d'EX-5.10, classe et attente de reprise (AN-8 à AN-11) ; `openssl ts -verify -queryfile` |
| `ct-5/ots/` | `point-k2-minimal.ots` (exemple d'EX-6.4), `point-k2-en-attente.ots`, `periode-1-en-attente.ots`, paire de mise à niveau | octets exacts ; O-1 à O-3 réussies, O-7 non exécutée ; resérialisation identique par `python-opentimestamps` (AN-17 à AN-19) |
| `ct-5/planification/` | Les vingt et une traces normatives de CT-5 §8.10 et annexe A.3 (heure nominale, prestataire injoignable, refus permanent et relève, réponse tardive, horloge suspecte, échéance remplacée, registre indisponible, redémarrage, mise à niveau OpenTimestamps, preuve de vie, file pleine, `min_interval_ms` ; révision 0.2 : refus puis preuve de vie, avec et sans redémarrage, file perdue, bascule d'époque, avec fichier perdu, registre indisponible à la clôture, mi-période à `n_T` impair, réponse hors profil, point manquant) | `expected` et `queue_after` reproduits à l'identique par `rejouerTrace` (AN-2, AN-4, AN-12, AN-13, AN-32 à AN-43, AN-49, AN-58) |
| `ct-5/reprise/` | Files avant et après `demarrage` (une demande par ligne, JCS intégral), fichiers d'époque | lignes finales égales ; une seule demande par `id` ; fusion des époques (AN-33) |
| `ct-5/completude/completude.json` | Quatre cas du contrôle de complétude au registre (CT-5 EX-10.7) : série complète, série réécrite et ancres orphelines, ancres hors d'ordre, émetteur, `docType` et fenêtre de blocs | `complete`, `orphans`, `out_of_order`, `attached` (AN-61) |
| `ct-5/cout/cout.json` | Les onze cas de CT-5 §12.3, à prix symbolique | six grandeurs par cas ; avec `a = 1`, égalité avec la table de CT-5 §4.6 (AN-59, AN-60) |
| `ct-5/verificateur-independant/` | Vérificateur Go écrit depuis la seule spécification, module séparé de ceux de `ct-1` à `ct-4` | zéro discordance (`go run . ..`) |
| `ct-5/confrontation/` | Programmes et sorties d'OpenSSL, de `python-opentimestamps` et de `transparency-dev/merkle` v0.0.2 (preuves de cohérence des vecteurs de CT-1 et des dossiers de CT-1 et CT-6, A.6) | concordance ; `test/confrontation.test.js` |

### CT-6 (`vecteurs/ct-6/`)

Disposition, générateur et confrontation fixés par l'annexe A de
[CT-6](CT-6-verificateur.md) (EX-A.1 à EX-A.12) :
`scripts/vecteurs/generer-ct6.mjs` (`npm run vecteurs:ct6`) rejoue tout à
l'identique ; ses entrées, lues et jamais réécrites, sont la capture du registre
(`registre/capture/`, réseau de développement, avec sa procédure de recapture,
EX-A.8), les clés RSA de test (`rfc3161/cles/*.cle.pem`) et `confrontation/`.
Les vecteurs de CT-1 et de CT-2 ne changent pas. Chaque cas et son attendu sont
décrits dans [`vecteurs/ct-6/INDEX.md`](vecteurs/ct-6/INDEX.md) ;
`test/verificateur.test.js` rejoue chaque dossier par
`scripts/verify/dossier.mjs` et valide chaque rapport JSON contre
`rapport-verification-v0`.

| Répertoire | Contenu (CT-6, annexe A) | Résultat attendu |
|---|---|---|
| `ct-6/ancres/` | Fichiers d'ancres de test, `ancres-test.json` et ses variantes (A.6) | entrées des dossiers |
| `ct-6/rfc3161/` | AC et TSA de test à clés RSA fixes et publiques, pour les tests seulement ; jetons sur le `periodHash` des trois manifestes de CT-1, `genTime` et numéros de série fixes ; une variante invalide par vérification T- ; CRL de test (A.3) | statuts de T-1 à T-11 ; `openssl ts -verify` |
| `ct-6/ots/` | Chaîne d'en-têtes Bitcoin synthétique `regtest`, preuve de travail réelle à la cible minimale ; preuves `.ots` au format officiel sur `periodHash` ; une variante invalide par vérification O- (A.4) | statuts de O-1 à O-7 ; `python-opentimestamps` |
| `ct-6/registre/` | Capture unique du réseau de développement (entrée) ; parties `registre.json`, `certificat-commit.json` et `validateurs.json` dérivées pour les périodes 1 et 2 (A.5) | hachages de blocs, racines des reçus, journaux décodés ; go-ethereum et noorcore |
| `ct-6/dossiers/` | `valide-seq-7-complet` (le dossier CT-1 `valide-seq-7` complété des cinq parties réservées) et ses variantes, et deux dossiers de décision refusée et expirée, chacun avec son `attendu.json` (A.7) ; révision 0.2 : dix-huit dossiers avec la partie `points-de-controle.json` (dix-sept la portent, un la déclare absente), valides et invalides, au moins un par vérification K-7 à K-9, dont le point contresigné de 09:35 retenu par le choix du point couvrant (CT-5 EX-10.2), le point de clôture et le double défaut de K-1 ; les cinquante dossiers existants inchangés (EX-A.13 à EX-A.17) | verdict, liste exacte des vérifications en échec, statuts des huit contrôles, avertissements dans l'ordre de EX-6.15, énoncé et borne (fragment FK et `facts.checkpoint` pour les dossiers avec la partie) |
| `ct-6/confrontation/` | Programmes et sorties des implémentations tierces : OpenSSL (`rfc3161/`), python-opentimestamps (`ots/`), go-ethereum et noorcore (`registre/`) (A.8) | concordance avec les `attendu.json` ; `test/confrontation.test.js` relie les sorties publiées aux vecteurs |
