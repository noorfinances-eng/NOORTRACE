# Vecteurs CT-9 — plan de tests

Produit par `scripts/vecteurs/generer-ct9.mjs` (`npm run vecteurs:ct9`) ; ne pas
l'éditer à la main. Spécification :
[`spec/CT-9-plan-de-tests.md`](../../CT-9-plan-de-tests.md), annexe A.

Le générateur lit les spécifications, `spec/vecteurs/ct-7/menaces.json`,
`test/*.test.js` et `.github/workflows/ci.yml` sans jamais les écrire
(EX-4.5). Il n'écrit ni n'efface `confrontation/` ni
`verificateur-independant/`. Deux exécutions donnent des fichiers identiques
(EX-A.1).

```bash
npm run vecteurs:ct9
npm run tests:couverture   # code 0 : règles (a) à (d) et EX-4.4 tiennent
```

## `catalogue.json`

Catalogue CT-9 0.2 du 2026-11-03 (schéma `plan-de-tests-v0`, racine) : 321
entrées, 6 justifications NC-, 82 risques acceptés, 117 lignes TC-. Une ligne
par entrée : identifiant, niveau, état, titre.

| Id | Niveau | État | Titre |
|---|---|---|---|
| TU-1 | TU- | exécutable | JCS v0 : forme canonique restreinte aux entiers (CT-1 §4) |
| TU-2 | TU- | exécutable | Ed25519 (RFC 8032) et dérivation des clés de test (CT-1 §6.2, §13) |
| TU-3 | TU- | exécutable | Événement : hachage, signature, approbation, rotation, pièces (CT-1 §5 à §8) |
| TU-4 | TU- | exécutable | Chaînage : `seq`, `prev_hash`, diagnostics nommés (CT-1 §7) |
| TU-5 | TU- | exécutable | Arbre de Merkle RFC 6962, preuves d'inclusion, période vide (CT-1 §9) |
| TU-6 | TU- | exécutable | Preuve de cohérence RFC 9162 §2.1.4 et points de contrôle (CT-1 §10.5 à §10.8) |
| TU-7 | TU- | exécutable | Manifeste de période : `periodHash`, signature, continuité, `anchorFingerprint` (CT-1 §10.1 à §10.4) |
| TU-8 | TU- | exécutable | Validation contre les schémas JSON de CT-1 (`validerSchema`) |
| TU-9 | TU- | exécutable | Dossier de preuve par la bibliothèque : assemblage, index, contrôles D-, P-, A- (CT-1 §11) |
| TU-10 | TU- | exécutable | Partie `attestation-perimetre.json` par la bibliothèque, AT-1 à AT-7 (CT-1 révision 0.4) |
| TU-11 | TU- | exécutable | Ligne de commande `scripts/verify/dossier.mjs` : codes 0, 1, 2 (CT-1 §11.4) |
| TU-12 | TU- | exécutable | Propriétés aléatoires du noyau : canonicalisation, hachage, chaînage, Merkle, signature |
| TU-13 | TU- | exécutable | Primitives de la console confrontées à `node:crypto`, `@noble/*` et `ethers` (CT-3 EX-13.32) |
| TU-14 | TU- | exécutable | Lecteur DER borné du vérificateur (CT-6 §9.3) |
| TU-15 | TU- | exécutable | Jeton RFC 3161 construit en mémoire : T-1 à T-11, N-1, AV-T- (CT-6 §9, §12.2, §15.2) |
| TU-16 | TU- | exécutable | Format `.ots`, en-têtes Bitcoin, O-1 à O-7 construits en mémoire (CT-6 §10, §15.2) |
| TU-17 | TU- | exécutable | Registre : RLP, hachage BFT, reçus, journaux, parties, R-1 à R-10 et N-4 construits en mémoire (CT-6 §11) |
| TU-18 | TU- | exécutable | Certificat de commit : parité du décodeur JavaScript avec le code Go de noorcore (CT-4 §9, CT-6 §11) |
| TU-19 | TU- | exécutable | Contrats du registre : `PeriodRegistry`, `RecorderRegistry`, signatures à seuil, déploiement (CT-4 §5) |
| TU-20 | TU- | exécutable | JCS intégral (RFC 8785 tel quel) et étendue des valeurs relayées (CT-2 §8.1, EX-4.20) |
| TU-21 | TU- | exécutable | Détecteurs exacts, politique de rédaction, motifs et budget (CT-2 §10) |
| TU-22 | TU- | exécutable | Analyseur SSE et formes consolidées des flux Anthropic, Chat Completions, Responses (CT-2 §5.4) |
| TU-23 | TU- | exécutable | Frontal MCP en bibliothèque : agrégation de `tools/list`, lecture d'une requête d'hôte, codes d'erreur, quotas (CT-2 §4.3, §4.4) |
| TU-24 | TU- | exécutable | Construction des événements, écrivain, segment, journal d'intention, reprise, horloge (CT-2 §7, §9, §12) |
| TU-25 | TU- | exécutable | Configuration et contrôles de démarrage (CT-2 §15, EX-7.15) |
| TU-26 | TU- | exécutable | Passerelle Gemini et format `gemini` du SDK, règles en bibliothèque (CT-2 §5.4.5, EX-5.28 à EX-5.36, EX-6.8) |
| TU-27 | TU- | exécutable | Ingestion OpenTelemetry en bibliothèque : décodage, classement, doublons, refus (CT-2 §6.8) |
| TU-28 | TU- | exécutable | Copies WORM et gel juridique en bibliothèque (CT-2 §12.6, §12.11) |
| TU-29 | TU- | exécutable | Coût annuel par agent : formule et contrôles d'entrée (CT-2 §16.4) |
| TU-30 | TU- | exécutable | Politique d'approbation : validation, évaluation, candidats, exemples de la spécification (CT-3 §3 à §6, §8.2) |
| TU-31 | TU- | exécutable | Tickets, remises, jeu d'approbateurs, mandataire en attente et échanges noyau ↔ service (CT-3 §7 à §12, §14 ; CT-2 §7.5) |
| TU-32 | TU- | exécutable | Console de référence en bibliothèque : annuaire, modèle d'affichage, requêtes, réponses, découverte, fichiers de clé, propriétés statiques (CT-3 §9, §12.9, §13) |
| TU-33 | TU- | exécutable | Console de référence dans Chromium : parcours nominal, refus, délai, changement de ticket, annuaire, comptes, inscription, politique du contenu (CT-3 EX-13.36) |
| TU-34 | TU- | exécutable | Mode observation en bibliothèque : `evaluerObservation`, marque, relais, configuration (CT-3 révision 0.4, CT-2 révision 0.6) |
| TU-35 | TU- | exécutable | Registre CT-4 : exigences vérifiables hors ligne, outil de référence hors ligne, parcours sur le réseau Hardhat en mémoire, capture derrière un pont synthétique (CT-4 §3 à §9) |
| TU-36 | TU- | exécutable | Planificateur d'ancrage en bibliothèque : comptages, coût, série des points, admission, complétude (CT-5 §3, §4, §10.3, §12) |
| TU-37 | TU- | exécutable | Attestation de périmètre et procès-verbal de cérémonie en bibliothèque : condensés, signatures, séparation des domaines, AT-1 à AT-4 (CT-7 §5.7, §5.8, §7.2, §7.7) |
| TU-38 | TU- | exécutable | Bibliothèques du déploiement et de l'exploitation : fichiers de conteneur, configuration rapide, archive autonome, outils donnés dès maintenant, configuration modèle de production (CT-8 §3.6, §4, §7.3, §8, §10.14) |
| TU-39 | TU- | exécutable | Outil du paquet réviseur : vérification, construction, instructions, corrections (CT-8 §13.5 à §13.11) |
| TV-1 | TV- | exécutable | `ct-1/cles/` : clés de test dérivées des graines |
| TV-2 | TV- | exécutable | `ct-1/jcs/cas-limites.json` : forme canonique ou refus |
| TV-3 | TV- | exécutable | `ct-1/journal-valide/` et les cinq journaux altérés : contrôles de la table 7.2 |
| TV-4 | TV- | exécutable | `ct-1/merkle/arbres.json` : racines et preuves d'inclusion |
| TV-5 | TV- | exécutable | `ct-1/merkle/coherence.json` et `ct-1/points-de-controle/` : preuves de cohérence, séries valides et invalides |
| TV-6 | TV- | exécutable | `ct-1/manifestes/` : trois périodes consécutives et un manifeste discontinu |
| TV-7 | TV- | exécutable | `ct-1/dossiers/` : le dossier valide et chaque dossier invalide, par la bibliothèque et par le vérificateur de CT-6 |
| TV-8 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-1` |
| TV-9 | TV- | exécutable | Vérificateur Go indépendant de CT-1 : zéro discordance sur `spec/vecteurs/ct-1` |
| TV-10 | TV- | exécutable | `ct-2/jcs-integral/cas.json` |
| TV-11 | TV- | exécutable | `ct-2/redaction/` : politiques, motifs, pièces rédigées, idempotence |
| TV-12 | TV- | exécutable | `ct-2/pieces-mcp/` : appels relayés ou refusés, agrégation de `tools/list` |
| TV-13 | TV- | exécutable | `ct-2/pieces-modele/` : Anthropic, OpenAI Chat Completions et Responses, Gemini |
| TV-14 | TV- | exécutable | `ct-2/otel/` : 48 cas d'ingestion OTLP en JSON et en protobuf |
| TV-15 | TV- | exécutable | `ct-2/worm/` : requêtes, états, périmètres, gardes, levées |
| TV-16 | TV- | exécutable | `ct-2/cout-agent/cas.json` : neuf cas de la formule |
| TV-17 | TV- | exécutable | `ct-2/evenements/journal-demo/` : chaîne, pièces, politique, intention, segment, dossier de seq 7 |
| TV-18 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-2` |
| TV-19 | TV- | exécutable | Vérificateur Go indépendant de CT-2 : zéro discordance sur `spec/vecteurs/ct-2` |
| TV-20 | TV- | exécutable | Confrontation tierce de `ct-2` : google-genai 2.33.0 et opentelemetry-proto 1.45.1 |
| TV-21 | TV- | exécutable | `ct-3/politiques/`, `politiques-invalides/`, `evaluation/`, `candidats/` : AP-1 à AP-17 |
| TV-22 | TV- | exécutable | `ct-3/acceptation/` rejoué par l'implémentation de référence : dix décisions, matériel sans attendu (CT-3 EX-A.4, EX-A.5) |
| TV-23 | TV- | exécutable | `ct-3/tickets/` : traces de cycle de vie, TK-1 à TK-13 |
| TV-24 | TV- | exécutable | `ct-3/decisions/` et `ct-3/signatures/normalisation.json` : remises acceptées et refusées, SG-1 à SG-7 |
| TV-25 | TV- | exécutable | `ct-3/annuaire/` : annuaires, messages, inscriptions, domaines, traces, contrôles, exports (AN-1 à AN-10) |
| TV-26 | TV- | exécutable | `ct-3/console/` : modèles, requêtes, réponses, découverte, fichiers de clé (CS-1 à CS-9) ; matériel de l'épreuve de lecture |
| TV-27 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-3` |
| TV-28 | TV- | exécutable | Vérificateur Go indépendant de CT-3 : zéro discordance sur `spec/vecteurs/ct-3` |
| TV-29 | TV- | exécutable | Confrontation tierce de `ct-3` : signatures par ethers 6 et eth-account 0.14.0 |
| TV-30 | TV- | exécutable | `ct-4/identifiants.json`, `doctypes.json`, `empreintes.json` : RG-1 à RG-4 |
| TV-31 | TV- | exécutable | `ct-4/condenses.json` : RG-5 à RG-13 |
| TV-32 | TV- | exécutable | `ct-4/appels.json` et `transactions.json` : RG-14, RG-15, confrontation à ethers et à la capture |
| TV-33 | TV- | exécutable | `ct-4/manifestes/` : RG-16 à RG-20, ancre `registry` dérivée |
| TV-34 | TV- | exécutable | `ct-4/demandes/` et `ct-4/inscription/` : schéma, OP-4, OP-6, OP-7 |
| TV-35 | TV- | exécutable | `ct-4/capture/` : CP-2 à CP-6, export des parties |
| TV-36 | TV- | exécutable | Complétude des familles de `ct-4` : chaque RG-, OP- hors ligne et CP- a un cas réussi et un cas en échec ; exemples annotés |
| TV-37 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-4` |
| TV-38 | TV- | exécutable | Vérificateur Go indépendant de CT-4 : zéro discordance sur `spec/vecteurs/ct-4` |
| TV-39 | TV- | exécutable | `ct-5/requetes/` : `TimeStampReq` DER exacte, nonce, refus |
| TV-40 | TV- | exécutable | `ct-5/reponses/` : classement des réponses de l'autorité de test |
| TV-41 | TV- | exécutable | `ct-5/ots/` : fichiers `.ots` reconstruits, mise à niveau |
| TV-42 | TV- | exécutable | `ct-5/planification/` et `ct-5/reprise/` : vingt et une traces du planificateur, files avant et après |
| TV-43 | TV- | exécutable | `ct-5/cout/` et `ct-5/completude/` : onze cas de coût, six cas de complétude |
| TV-44 | TV- | exécutable | Vecteurs de CT-1 et de CT-6 inchangés par CT-5 ; aucun secret, prix ni adresse dans `ct-5` |
| TV-45 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-5` |
| TV-46 | TV- | exécutable | Vérificateur Go indépendant de CT-5 : zéro discordance sur `spec/vecteurs/ct-5` |
| TV-47 | TV- | exécutable | Confrontation tierce de `ct-5` : openssl, python-opentimestamps, transparency-dev/merkle |
| TV-48 | TV- | exécutable | `ct-6/rfc3161/` : jetons, clés, CRL, statuts T-1 à T-11, confrontation à `openssl ts -verify` |
| TV-49 | TV- | exécutable | `ct-6/ots/` : en-têtes synthétiques, preuves, statuts O-1 à O-7 |
| TV-50 | TV- | exécutable | `ct-6/registre/` : parties dérivées de la capture, variantes, R-1 à R-10 et N-4 |
| TV-51 | TV- | exécutable | `ct-6/ancres/` : fichiers d'ancres de test conformes à `ancres-confiance-v0` |
| TV-52 | TV- | exécutable | `ct-6/dossiers/` : dossiers complets, verdicts, énoncés, V-1 à V-10 (rapport comparé à `attendu.json`) |
| TV-53 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-6` (dossiers, rfc3161, ots, registre) |
| TV-54 | TV- | exécutable | Confrontation tierce de `ct-6` : openssl, python-opentimestamps, go-ethereum et noorcore |
| TV-55 | TV- | exécutable, complément à écrire | Vérificateur Go indépendant de CT-6 (binaire de CT-6 §14) : zéro discordance sur `ct-6/dossiers` |
| TV-56 | TV- | exécutable | `ct-7/menaces.json`, tables 3.2 à 3.5 et vérificateur de renvois : RV-1 à RV-9, table TR- de CT-7 |
| TV-57 | TV- | exécutable | `ct-7/ceremonies/` : procès-verbaux valides et invalides, CR-1 à CR-12, commande `ceremonie.mjs` |
| TV-58 | TV- | exécutable | `ct-7/attestations/` : exemple, 18 cas hors dossier, signatures croisées, outil de référence |
| TV-59 | TV- | exécutable | `ct-7/matrice-conformite.json` et `ct-7/matrice/invalides/` : MX-1 à MX-9, tables 8.2, 8.4, 8.9 et clauses cellule par cellule |
| TV-60 | TV- | exécutable | `ct-7/cles-de-test.json` : clés publiques et adresses recalculées |
| TV-61 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-7` ; grilles des épreuves à part des consignes |
| TV-62 | TV- | exécutable | Vérificateur Go indépendant de CT-7 : zéro discordance sur `spec/vecteurs/ct-7` |
| TV-63 | TV- | exécutable | Confrontation tierce de `ct-7` : signatures des procès-verbaux et des attestations par ethers et eth-account |
| TV-64 | TV- | exécutable | `ct-8/conteneurs/` : 36 cas, CO-1 à CO-14 |
| TV-65 | TV- | exécutable | `ct-8/controle-prealable/` : 33 cas, IP-1 à IP-13, collecte réelle sans réseau |
| TV-66 | TV- | exécutable | `ct-8/dimensionnement/` : 16 cas, DM-1 à DM-22, tables 9.5, 9.6 et valeurs de CT-8 EX-14.2 |
| TV-67 | TV- | exécutable | Table de traçabilité de CT-8 : `renvois.mjs`, TC-1 à TC-115 |
| TV-68 | TV- | exécutable | Chaînes interdites dans `deploiement/` et `spec/vecteurs/ct-8/` |
| TV-69 | TV- | exécutable | `ct-8/observation/` : marques, correspondance avec CT-3, journal d'exemple, rapport, OB-1 à OB-6 |
| TV-70 | TV- | exécutable | `ct-8/journaux/`, `proces-verbaux/`, `consultations/` : vérification de journal, PV-1 à PV-10, CA-1 à CA-6, runbooks SV-8 |
| TV-71 | TV- | exécutable | `ct-8/paquets/` : dix-sept cas de `cas.json`, deux constructions identiques, recette GNU tar |
| TV-72 | TV- | exécutable | Matériel des épreuves de CT-8 §14 présent et cohérent : consignes, grilles, entrées de dimensionnement |
| TV-73 | TV- | exécutable | Génération déterministe de `spec/vecteurs/ct-8` |
| TV-74 | TV- | exécutable | Vérificateur Go indépendant de CT-8 : zéro discordance sur `spec/vecteurs/ct-8` |
| TV-75 | TV- | exécutable | Confrontation tierce de `ct-8` : GNU tar, `sha256sum`, `jq`, `tarfile` de Python |
| TV-76 | TV- | à écrire (étape 7) | `ct-8/supervision/` : SV-1 à SV-7, règles d'alerte, extracteur, tableau de bord |
| TI-1 | TI- | à écrire (étape 8) | Export OpenTelemetry GenAI d'un événement (CT-1 §12.1) validé par le registre des conventions |
| TI-2 | TI- | à écrire (étape 8) | Export au format du projet IETF « agent audit trail » (CT-1 §12.2) relu par un vérificateur du projet |
| TI-3 | TI- | exécutable | Protocole MCP réel : client de référence (stdio et Streamable HTTP, ère moderne) à travers le frontal |
| TI-4 | TI- | à écrire (étape 8) | Intégration Anthropic : SDK officiel avec `ANTHROPIC_BASE_URL` vers la passerelle (hors flux et flux) |
| TI-5 | TI- | à écrire (étape 8) | Intégration OpenAI : Chat Completions et Responses par le SDK officiel vers la passerelle |
| TI-6 | TI- | à écrire (étape 8) | Intégration Gemini : `google-genai` vers la passerelle (route `gemini`, `x-goog-api-key`) |
| TI-7 | TI- | à écrire (étape 8) | Intégration LangChain et LangGraph : intergiciel `MiddlewareNoortrace`, `wrap_tool_call` |
| TI-8 | TI- | à écrire (étape 8) | Intégration CrewAI : crochets `before_tool_call` et `after_tool_call` enregistrés en dernier |
| TI-9 | TI- | à écrire (étape 8) | Intégration LlamaIndex : enveloppe de chaque outil |
| TI-10 | TI- | à écrire (étape 8) | Intégration LiteLLM : `CustomLogger` en bibliothèque et LiteLLM en mandataire devant la passerelle |
| TI-11 | TI- | à écrire (étape 8) | Intégration OpenTelemetry : agent instrumenté par un SDK OpenTelemetry vers le point d'entrée OTLP de l'enregistreur |
| TI-12 | TI- | exécutable | Requêtes OTLP confrontées à `opentelemetry-proto` et réponses `ExportTraceServiceResponse` exactes |
| TI-13 | TI- | exécutable | SDK Python et TypeScript : interface publique, versions de langage, aucune exception vers l'agent |
| TI-14 | TI- | à écrire (étape 6) | Canal réel noyau ↔ service d'approbation et console ↔ service : authentification, `evaluer`, `GET /v0/etat`, sessions |
| TI-15 | TI- | à écrire (étape 7) | Supports WORM réels (S3, Azure, GCS) : requêtes exactes, verrou, rétention, journal d'accès |
| TI-16 | TI- | à écrire (étape 5) | Prestataires RFC 3161 et calendriers OpenTimestamps réels : fiche de prestataire, `min_interval_ms`, qualification |
| TI-17 | TI- | à écrire (étape 5) | Serveur RFC 3161 interne : AN-22 à AN-31 vérifiées sur un jeton émis, épreuve de redémarrage (AN-26) |
| TI-18 | TI- | exécutable | Nœud noorcore et certificat de commit : JSON-RPC `noor_getCommitCertificate`, parité Go/JavaScript, confrontation go-ethereum |
| TI-19 | TI- | exécutable | Mode ICAP : raccord à un mandataire existant, sources admises |
| TI-20 | TI- | exécutable | Export des pièces d'un dossier vers un paquet réviseur lu par des outils tiers (GNU tar, `tarfile`) |
| TE-1 | TE- | à écrire (étape 8) | Cas de démonstration « assurance » : agent de souscription et de tarification, de la capture au dossier vérifié |
| TE-2 | TE- | à écrire (étape 8) | Cas de démonstration « administration » : agent qui instruit des demandes de prestations publiques |
| TE-3 | TE- | à écrire (étape 8) | Démonstration de référence en une commande : `docker compose up`, moins de deux minutes, verdict imprimé (CT-2 §19) |
| TE-4 | TE- | exécutable | Parcours CT-4 §7 sur le réseau de développement noorcore : client inscrit, racine ancrée, période close, certificats capturés |
| TE-5 | TE- | exécutable | De l'événement au dossier vérifié sur les vecteurs : `journal-demo` de CT-2, export des parties du registre, vérificateur de CT-6 |
| TE-6 | TE- | à écrire (étape 7) | Installation rapide IR-1 à IR-8 sur un hôte neuf, premier dossier vérifié |
| TE-7 | TE- | à écrire (étape 7) | Installation complète IC-1 à IC-18 sur une machine vierge, en moins d'une journée, avec le seul document |
| TE-8 | TE- | à écrire (étape 7) | Flux réseau FL-1 à FL-31 observés sur le déploiement de test et runbooks RB-1 à RB-8 rejoués |
| TE-9 | TE- | à écrire (étape 7) | Sauvegarde et reprise : chemins A, B et C, continuité de la chaîne, procès-verbaux |
| TE-10 | TE- | à écrire (étape 7) | Mode observation de bout en bout : capture sans blocage, rapport d'observation, passage au mode bloquant |
| TE-11 | TE- | exécutable | Haute disponibilité à écrivain unique : bascule du bail, pertes admises, jeton de clôture (CT-2 §13) |
| TE-12 | TE- | à écrire (étape 5) | Ancrage complet d'une racine : point de contrôle, ancre au registre, jeton RFC 3161, preuve OpenTimestamps, dossier vérifié hors ligne |
| TE-13 | TE- | à écrire (étape 6) | Console : un approbateur s'inscrit, signe une décision depuis son portefeuille, le dossier exporté passe le vérificateur |
| TE-14 | TE- | à écrire (étape 5) | Journal de l'enregistreur sur lui-même : JS-1 à JS-12 observés sur le démon |
| TE-15 | TE- | à écrire (étape 7) | Construction des images de référence : reproductibilité, `docker inspect`, volume nommé, compagnon d'immuabilité |
| TE-16 | TE- | à écrire (étape 4) | Matrice des pannes de CT-2 §14 rejouée sur le démon : classification des outils, ce qui est rendu à l'hôte, ce qui est journalisé, mode dégradé |
| TE-17 | TE- | à écrire (étape 7) | Supervision en charge : alertes prescrites levées sur incident, métriques `noortrace_*`, dossier produit sous charge vérifié |
| TA-1 | TA- | à écrire (étape 8) | Réponse retirée : Règle de sortie du pare-feu : seul le mandataire joint le serveur d'outils HTTP (CT-2 EX-4.1, §4.9) |
| TA-2 | TA- | exécutable | Réponse retirée : launched_by tiré de la configuration de la connexion d'hôte, jamais de l'hôte (CT-2 EX-7.2, EX-7.3) |
| TA-3 | TA- | exécutable | Réponse retirée : Plafond max_calls d'une fenêtre d'approbation (CT-3 EX-5.2, EX-5.5) |
| TA-4 | TA- | exécutable | Réponse retirée : Analyse stricte : clé en double refusée, nombre non représentable refusé (CT-2 EX-4.43, EX-4.44) |
| TA-5 | TA- | exécutable, complément à écrire | Réponse retirée : Consommation unique d'une approbation et délai de reconnaissance (CT-3 EX-7.17, EX-7.18) ; RL-1 à RL-4 côté enregistreur (CT-2 EX-7.21) |
| TA-6 | TA- | exécutable | Réponse retirée : Plafond de tickets ouverts par demandeur (CT-3 EX-14.1) |
| TA-7 | TA- | exécutable | Réponse retirée : Espace noortrace.* réservé, aucun outil propre annoncé (CT-2 EX-4.2, CT-1 E-3) ; empreinte de chaque définition et pièce de définition (CT-2 EX-4.16, EX-4.45) |
| TA-8 | TA- | exécutable | Réponse retirée : Authentification de tout appelant HTTP, comparaison en temps constant, prise locale 0660 (CT-2 EX-18.3, EX-4.39, EX-18.1) |
| TA-9 | TA- | exécutable | Réponse retirée : Utilisateur distinct, bac à sable et environnement réduit des serveurs stdio (CT-2 EX-3.4, EX-3.5, EX-18.4) ; secrets en fichiers 0400 (EX-15.3) |
| TA-10 | TA- | exécutable | Réponse retirée : Intention durable avant relais et reprise des intentions (CT-2 EX-4.19, EX-12.12, EX-12.14) ; code -31017 (EX-4.46) |
| TA-11 | TA- | exécutable | Réponse retirée : Clé du fournisseur tenue par la passerelle seule en mode propre (CT-2 EX-5.8) ; pare-feu de sortie (§4.9, EX-6.2) |
| TA-12 | TA- | exécutable | Réponse retirée : Clients ICAP authentifiés (mTLS ou allowed_sources), l'un des deux exigé en production (CT-2 EX-5.3 ; CT-7 EX-3.15) |
| TA-13 | TA- | exécutable | Réponse retirée : Refus d'une requête qui déclare des serveurs MCP au fournisseur, sauf relayer (CT-2 EX-5.32) |
| TA-14 | TA- | exécutable, complément à écrire | Réponse retirée : Rang de chaque mode écrit et contrôlé (CT-2 §5.1, EX-5.1, EX-5.6) ; mode déclaré dans l'attestation (CT-7 §7) |
| TA-15 | TA- | exécutable | Réponse retirée : Rang de preuve écrit et alias annoncés dans la chaîne ; événement déclaratif reconnaissable au préfixe <alias>__ (CT-2 §6.7, EX-6.24, EX-6.1) |
| TA-16 | TA- | exécutable | Réponse retirée : Noms limités au préfixe de la source, sources authentifiées, bornes (CT-2 EX-6.37, EX-6.40, EX-6.28, EX-4.47) |
| TA-17 | TA- | exécutable | Réponse retirée : Points de contrôle contresignés et ancrés (CT-2 EX-12.24, CT-1 §10.9, CT-5 EX-4.3) ; K-7 à K-9 au vérificateur (CT-6 §5.4) |
| TA-18 | TA- | à écrire (étape 8) | Réponse retirée : Rapprochement de l'usage des fournisseurs, clé par clé (CT-7 EX-3.8) |
| TA-19 | TA- | exécutable | Réponse retirée : Bail, époque, jeton de clôture vérifié par le stockage, contrôle après écriture (CT-2 EX-13.1, EX-13.4 à EX-13.6, EX-13.10) |
| TA-20 | TA- | exécutable | Réponse retirée : Relecture et troncature d'une fin incomplète ; mode dégradé stockage (CT-2 EX-12.8, EX-12.10, EX-12.11) |
| TA-21 | TA- | exécutable | Réponse retirée : ts non décroissant et blocage sur saut en avant (CT-2 EX-7.10, EX-7.13 ; CT-1 §5.2) |
| TA-22 | TA- | à écrire (étape 8) | Réponse retirée : Aucun droit de l'hôte ni de l'agent sur storage.root (CT-2 EX-3.2, EX-18.5) |
| TA-23 | TA- | exécutable | Réponse retirée : Toute version de politique annoncée dans la chaîne avant usage (CT-2 EX-9.1, EX-9.2, EX-8.11) |
| TA-24 | TA- | exécutable | Réponse retirée : Coffre chiffré à clé propre ; déchiffrement à deux personnes consigné (CT-2 EX-10.22, CT-7 EX-3.11) |
| TA-25 | TA- | à écrire (étape 7) | Réponse retirée : Surfaces d'écoute exhaustives, moindre privilège (CT-2 EX-18.1, EX-18.2, EX-18.4, EX-18.7) ; version et empreinte de l'image consignées (EX-18.6, CT-7 EX-3.14) |
| TA-26 | TA- | exécutable | Réponse retirée : Points de contrôle à chaque instant aligné (preuve de vie, CT-2 EX-12.24) ; lignes startup, lease_acquired, lease_lost (EX-17.2) ; annonce de reprise (CT-7 PA-1) |
| TA-27 | TA- | exécutable | Réponse retirée : Rétention par défaut en mode Compliance, contrôle du verrou (CT-2 EX-12.30, EX-12.32, EX-12.33) |
| TA-28 | TA- | exécutable | Réponse retirée : Règle de garde de la levée par deux personnes (CT-2 EX-12.37, EX-12.38) |
| TA-29 | TA- | à écrire (étape 7) | Réponse retirée : Copie de chaque segment fermé, comparaison horaire (CT-2 EX-12.16, EX-12.18, EX-17.5) |
| TA-30 | TA- | exécutable | Réponse retirée : Classe D refusée en production (CT-2 EX-11.8) ; non-exportabilité, mémoire protégée (EX-11.5, EX-18.7) |
| TA-31 | TA- | exécutable | Réponse retirée : Rapprochement mensuel des appels de signature avec les objets signés (CT-7 EX-3.7) ; identité d'usage seule (CT-2 EX-11.4, EX-11.3) |
| TA-32 | TA- | exécutable | Réponse retirée : Cérémonie à deux personnes au moins pour toute opération d'administration (CT-7 EX-5.1, EX-5.2) ; CR-2 |
| TA-33 | TA- | exécutable | Réponse retirée : Mode dégradé « clé » bloquant sur signataire injoignable sans reprise (CT-2 §17.4) ; rupture de journal (EX-11.16) |
| TA-34 | TA- | exécutable | Réponse retirée : Le contrôle 8 écarte les ancres d'une clé révoquée ou non inscrite pour la clé du manifeste (CT-6 R-10) ; provision bornée (CT-4 EX-4.20, EX-8.18) |
| TA-35 | TA- | à écrire (étape 8) | Réponse retirée : La clé de l'approbateur naît chez lui ; parcours par fichier seulement permis, absent de la page de référence (CT-3 EX-3.4, EX-13.1, EX-13.28, EX-13.31) |
| TA-36 | TA- | exécutable | Réponse retirée : « Une personne, une clé » (CT-3 EX-8.11, EX-13.10 ; CT-4 EX-7.8) ; CR-8, CR-11, CR-2 adresses distinctes |
| TA-37 | TA- | exécutable | Réponse retirée : Clé de gouvernance en classe A à C, jamais D (CT-4 EX-8.21, CT-7 EX-4.2) ; CR-6 |
| TA-38 | TA- | exécutable | Réponse retirée : Jeu épinglé par la politique (CT-3 EX-8.1, EX-8.6) ; garde matérielle de la clé de l'exploitant (CT-4 EX-5.4) |
| TA-39 | TA- | exécutable | Réponse retirée : Aucune sauvegarde ni réplication de la clé de validateur (CT-4 EX-10.7, EX-10.9 ; CT-7 EX-4.4) ; CR-7 |
| TA-40 | TA- | exécutable, complément à écrire | Réponse retirée : Destinataires admis et plafond quotidien de l'approvisionnement (CT-4 EX-8.20) |
| TA-41 | TA- | à écrire (étape 5) | Réponse retirée : Secrets par référence, jamais dans la file, les traces ni le journal (CT-5 EX-4.8, AN-43) |
| TA-42 | TA- | exécutable, complément à écrire | Réponse retirée : Clé du serveur RFC 3161 interne hors de l'hôte, classe A à C (CT-5 EX-7.3) ; CR-6 |
| TA-43 | TA- | exécutable, complément à écrire | Réponse retirée : Références de secrets, fichiers 0400, jamais écrits ni journalisés (CT-2 EX-15.3, EX-18.4, EX-17.3) |
| TA-44 | TA- | exécutable | Réponse retirée : Vérification de toute remise par le noyau : SG-5 signatures, SG-6 jeu (CT-2 EX-7.5 ; CT-3 SG-5, SG-6) |
| TA-45 | TA- | exécutable | Réponse retirée : Console qui recalcule D_A et recouvre l'adresse sur son propre condensé (CT-3 EX-9.6, EX-9.17, EX-9.21) |
| TA-46 | TA- | exécutable | Réponse retirée : Aucun choix implicite, doublons d'uuid exclus (CT-3 EX-13.22) |
| TA-47 | TA- | exécutable | Réponse retirée : Adresse jamais réattribuée, preuve de possession nommant l'identité, nonce unique (CT-3 EX-13.10, EX-13.13, EX-13.15) |
| TA-48 | TA- | exécutable | Réponse retirée : Séparation du demandeur vérifiée par le noyau (CT-3 EX-10.2, SG-7) ; seuil d'adresses distinctes (CT-1 A-3) |
| TA-49 | TA- | exécutable | Réponse retirée : Normalisation et refus des formes non canoniques par le noyau, sans déléguer à une bibliothèque (CT-3 EX-9.3, EX-9.22, SG-5) |
| TA-50 | TA- | exécutable | Réponse retirée : Seuil effectif qui ne baisse jamais, membres ajoutés signalés (CT-3 EX-8.5 à EX-8.7) |
| TA-51 | TA- | à écrire (étape 6) | Réponse retirée : Jeu lu auprès d'un validateur du client ou partenaire (CT-3 EX-8.2 ; CT-7 EX-3.10) |
| TA-52 | TA- | à écrire (étape 8) | Réponse retirée : Parcours c (relais de portefeuille) désactivé par défaut, échéance bornée, code jamais journalisé (CT-3 EX-13.27) |
| TA-53 | TA- | exécutable, complément à écrire | Réponse retirée : Réassignation sur demande écrite consignée, jeu administré par la même clé de gouvernance (CT-4 EX-8.10) ; OP-5 |
| TA-54 | TA- | exécutable | Réponse retirée : Quorum calculé sur le jeu du réviseur (CT-6 R-2) ; au plus f validateurs par opérateur (CT-4 EX-4.12) |
| TA-55 | TA- | à écrire (étape 8) | Réponse retirée : Garde d'admission par client, RPC des validateurs fermés (CT-4 EX-10.8, EX-10.3, EX-8.15) |
| TA-56 | TA- | exécutable | Réponse retirée : Certificat vérifié contre le jeu du manifeste avant d'être tenu pour capturé (CT-4 CP-1, CP-4) |
| TA-57 | TA- | à écrire (étape 8) | Réponse retirée : Identifiant EVM, adresse, étiquette et org_id dans chaque condensé (CT-4 EX-4.8, §6.6) ; RG-6 à RG-11, RG-13 |
| TA-58 | TA- | à écrire (étape 8) | Réponse retirée : Ancre du registre envoyée avant la requête d'horodatage, aucun nouvel essai après empreinte_squattee, incident consigné (CT-4 EX-8.4, EX-8.6 ; CT-5 EX-4.7, EX-9.6, EX-9.7) |
| TA-59 | TA- | exécutable | Réponse retirée : Adresse du contrat comparée à l'ancre (CT-6 R-8) ; aucune mise à niveau en place (CT-4 EX-5.9, EX-5.10) |
| TA-60 | TA- | exécutable | Réponse retirée : Contrôle de genTime à l'acquisition qui marque le jeton sans le refuser (CT-5 EX-5.11) |
| TA-61 | TA- | exécutable | Réponse retirée : Égalité stricte de l'empreinte recalculée : T-2, O-2 (et T-5, T-7, O-4, O-5), K-7 et K-9 pour un point (CT-6, CT-1 K-7, K-9) |
| TA-62 | TA- | exécutable, complément à écrire | Réponse retirée : Relève par le secours et file durable (CT-5 EX-5.7, EX-8.5) ; deux calendriers, min_responses (EX-4.9, EX-6.6, EX-8.11) |
| TA-63 | TA- | exécutable | Réponse retirée : Alerte point_manquant quand aucun point n'est admis pendant plus de 2 × c_K (CT-5 EX-8.15, §8.9) |
| TA-64 | TA- | exécutable | Réponse retirée : Reconstruction de la file au démarrage, alerte file_perdue (CT-5 EX-8.5, EX-8.12, EX-8.14) |
| TA-65 | TA- | exécutable | Réponse retirée : Statut qualifié établi sur la liste de confiance, jamais sur une déclaration (CT-5 EX-5.9 ; AN-1 règle 4) |
| TA-66 | TA- | exécutable, complément à écrire | Réponse retirée : Vérificateurs indépendants confrontés sur les vecteurs (CT-6 §3.1) ; binaire reproductible (EX-14.6, EX-14.8) |
| TA-67 | TA- | exécutable | Réponse retirée : Aucune ancre tirée du dossier ; clés d'enregistreur comparées au fichier d'ancres (CT-6 EX-3.3, EX-3.4, EX-12.1, N-3) |
| TA-68 | TA- | exécutable, complément à écrire | Réponse retirée : Lecture DER stricte, bornes, aucun octet en trop (CT-6 EX-15.1 à EX-15.3 ; T-1, O-1) |
| TA-69 | TA- | exécutable | Réponse retirée : Recalcul de tout contre les ancres du réviseur : R-4, R-6, R-7, R-8, R-9, R-11 ; K-1, K-4, K-5, K-8 (CT-6, CT-1) |
| TA-70 | TA- | exécutable | Réponse retirée : Travail recalculé au-dessus du point de contrôle du réviseur, profondeur minimale (CT-6 O-5, EX-10.9) |
| TA-71 | TA- | exécutable | Réponse retirée : Identifiant de chaîne de l'ancre comparé (CT-6 R-4) ; manifeste en révisions publiées et recoupement (CT-4 EX-4.25, RG-19 ; CT-6 §12.5) |
| TA-72 | TA- | exécutable | Réponse retirée : Seules des empreintes de 32 octets, des clés publiques et des identifiants sont écrits au registre (CT-4 §3.4 ; CT-5 §13) |
| TA-73 | TA- | exécutable, complément à écrire | Réponse retirée : Relais et approvisionnement sur confirmation hors bande consignée (CT-4 EX-8.21) ; demande consignée (CT-7 EX-5.1) |
| TA-74 | TA- | exécutable | Réponse retirée : Couverture de l'événement par le point (CT-1 K-4) ; série des points publiée (CT-5 §10.2) ; ancres extérieures (CT-6 §3.4) |
| TA-75 | TA- | à écrire (étape 7) | Réponse retirée : Relecture du registre des gels par un rôle Lecteur hors du démon (CT-2 EX-17.7, EX-18.9) ; métriques publiques (EX-17.1) |
| TA-76 | TA- | exécutable | Réponse retirée : Réponses tardives rejetées (CT-5 EX-5.11) ; TLS vérifié, nonce (EX-5.5, EX-6.2) |
| TA-77 | TA- | à écrire (étape 6) | Réponse retirée : Canal du service authentifié (CT-3 EX-12.2 ; CT-2 EX-18.8, EX-18.3) |
| TA-78 | TA- | exécutable | Réponse retirée : Périmètre rapporté « déclaré, non prouvé », jamais compté parmi ce que le dossier prouve (CT-7 EX-7.1, EX-7.17 ; CT-6 EX-6.19, EX-7.3) |
| TA-79 | TA- | exécutable | Réponse retirée : org_id et journal_id de l'attestation comparés à l'événement prouvé (CT-1 AT-5 ; CT-7 EX-7.16) |
| TA-80 | TA- | exécutable | Réponse retirée : ts de l'événement dans validity (CT-1 AT-5) ; renouvellement avant validity.until (CT-7 EX-7.5) |
| TA-81 | TA- | exécutable | Réponse retirée : Signature canonique recouvrée sur M et égale à l'adresse déclarée (CT-1 AT-3 ; CT-7 EX-7.6) ; AT-4 |
| TA-82 | TA- | exécutable | Réponse retirée : Avertissement AV-AT-2 quand le jeu déclaré diffère de approbations.json (CT-6 §5.5) ; set_source dans l'énoncé (CT-7 EX-7.17) |
| TA-83 | TA- | exécutable | Réponse retirée : Préfixe propre P_P et Keccak-256, D_P recalculé depuis le fichier (CT-7 EX-7.7, EX-7.8) |
| TA-84 | TA- | exécutable | Réponse retirée : Signature de l'inscription vérifiée sous la clé de l'événement prouvé (CT-1 AT-6 ; CT-7 EX-7.10) |
| TA-85 | TA- | exécutable | Réponse retirée : Sans inscription, AT-6 et AT-7 non exécutées et clause fixe de FP (CT-7 EX-7.12 ; CT-6 EX-6.19) |
| TA-86 | TA- | exécutable | Réponse retirée : seq et ts de l'inscription au plus ceux de l'événement prouvé (CT-1 AT-6 ; CT-7 EX-7.13) |
| TA-87 | TA- | exécutable | Réponse retirée : Ni secret, ni adresse IP, ni règles de sortie dans l'attestation (CT-7 EX-7.3) |
| TA-88 | TA- | à écrire (étape 4) | Réponse retirée : Nouvelle attestation dès qu'un élément change (CT-7 EX-7.5) ; consigne perimeter_unlisted_host et métrique d'échéance (PA-10, PA-11) |
| TA-89 | TA- | exécutable | Réponse retirée : Limites de taille de la partie et aucune AT- sans effet sur le verdict (CT-6 EX-4.15, EX-5.11, V-10) |
| TA-90 | TA- | exécutable | Réponse retirée : AT-6 non exécutée (ancre_absente) quand la clé de l'inscription n'est pas celle de l'événement prouvé (CT-1 AT-6 ; CT-6 EX-5.12, EX-6.19) |
| TA-91 | TA- | exécutable | Réponse retirée : AT-7 ne compare que des noms ; FP dit « de même nom », jamais la vigueur (CT-1 AT-7 ; CT-6 EX-6.19) |
| TA-92 | TA- | exécutable | Réponse retirée : Témoin distinct de l'exécutant à chaque étape, l'auditeur s'ajoutant sans le remplacer (CR-4 ; CT-7 EX-5.9, EX-5.2) ; ancre du réviseur sous la condition d'EX-5.10 |
| TA-93 | TA- | à écrire (étape 8) | Réponse retirée : D_C ancré par un jeton RFC 3161 joint ou une inscription au registre en production (CT-7 EX-5.11) ; recoupement avec l'inscription (EX-5.10) |
| TA-94 | TA- | exécutable | Réponse retirée : CR-12 : restauration avec purpose_details k, n et au moins k détenteurs de part (CT-7 EX-5.9, EX-5.5) |
| TA-95 | TA- | à écrire (étape 8) | Réponse retirée : Le témoin constate l'identité distincte de chaque détenteur de part et le consigne (CT-7 EX-5.2, §5.9) |
| TA-96 | TA- | à écrire (étape 8) | Réponse retirée : Changements de policy annoncés dans la chaîne (CT-2 EX-9.2) ; copie WORM des fichiers tournés du journal d'exploitation (PA-18) |
| TA-97 | TA- | à écrire (étape 8) | Réponse retirée : Comparaison du condensé à un second outil indépendant (CT-7 EX-5.8, EX-7.8, EX-A.21) |
| TA-98 | TA- | exécutable | Réponse retirée : Inscription exigée dès que possible (CT-7 EX-7.5) ; clause fixe de FP (CT-6 EX-6.19) |
| TA-99 | TA- | à écrire (étape 8) | Scénario du plan : l'agent supprime ou réécrit (TA-1, TA-2, TA-3, TA-4, TA-5, TA-6, TA-7, TA-9, TA-15, TA-22) |
| TA-100 | TA- | à écrire (étape 8) | Scénario du plan : l'opérateur réécrit après coup (TA-17, TA-18, TA-19, TA-23, TA-26, TA-27, TA-28, TA-74, TA-84, TA-85, TA-86, TA-96) |
| TA-101 | TA- | à écrire (étape 8) | Scénario du plan : l'horloge est manipulée (TA-21, TA-60, TA-76, TA-93) |
| TA-102 | TA- | à écrire (étape 8) | Scénario du plan : l'enregistreur tombe (TA-10, TA-19, TA-20, TA-26, TA-29, TA-33, TA-64) |
| TA-103 | TA- | à écrire (étape 8) | Scénario du plan : un prestataire est injoignable (TA-55, TA-58, TA-62, TA-63, TA-76) |
| TM-1 | TM- | à écrire (étape 8) | Latence ajoutée par appel relayé (CT-2 §16.1) : p50 ≤ 5 ms, p99 ≤ 50 ms |
| TM-2 | TM- | à écrire (étape 8) | Latence ajoutée au premier octet d'un flux SSE (CT-2 §16.1) : ≤ 10 ms pour chaque octet |
| TM-3 | TM- | à écrire (étape 8) | Débit : événements rendus durables par seconde et par instance (CT-2 §16.1) : ≥ 500 |
| TM-4 | TM- | à écrire (étape 8) | Latence ajoutée par échange de modèle hors flux (CT-2 §16.1) : p50 ≤ 5 ms, p99 ≤ 50 ms |
| TM-5 | TM- | à écrire (étape 8) | Durée d'un appel `sign` du signataire, publiée par classe de backend (CT-2 §16.1), sans cible |
| TM-6 | TM- | exécutable | Octets par événement sur les vecteurs publiés (CT-2 §16.1 : attendu de 2 à 3 KiB ; la ligne de l'annexe A fait 2 465 octets) |
| TM-7 | TM- | à écrire (étape 8) | Octets par événement et octets de pièces par appel en charge (CT-2 §16.1), sans cible |
| TM-8 | TM- | à écrire (étape 8) | Reprise : relecture du dernier segment et du journal d'intention au démarrage (CT-2 EX-12.10) : ≤ 2 s pour 256 MiB |
| TM-9 | TM- | à écrire (étape 8) | Mémoire résidente à vide et sous charge ; `m_0` et `M_tamp` du dimensionnement (CT-2 §16.1 ; CT-8 §9.2, §9.3) |
| TM-10 | TM- | exécutable | P-1 sur les vecteurs : cadence des points d'une série publiée, `checkpoint_ts − ts ≤ c_K + 1 s` (CT-5 §3.6, AN-2) |
| TM-11 | TM- | à écrire (étape 5) | P-1 sur le réseau de développement : série réelle produite par l'enregistreur, `checkpoint_ts − ts ≤ 61 s` |
| TM-12 | TM- | à écrire (étape 5) | P-2 : inclusion de l'ancre du point au registre, reçu reçu au plus `inclusion_alert_s` (60 s) après `checkpoint_ts` |
| TM-13 | TM- | à écrire (étape 5) | P-3 : contresignature RFC 3161 au plus `c_T + d_jeton` après l'événement, `d_jeton` rapporté avec ses quatre composantes (CT-5 EX-3.5) |
| TM-14 | TM- | à écrire (étape 5) | P-4 : clôture horaire contresignée par un prestataire qualifié et horodatée par OpenTimestamps auprès d'au moins deux calendriers |
| TM-15 | TM- | exécutable | P-5 : un dossier se vérifie hors ligne, sans réseau ni concours du fournisseur, points de contrôle compris |
| TM-16 | TM- | exécutable, complément à écrire | P-6 : copie à verrou d'objet des points, ancres et manifestes, SHA-256 égal, mode et rétention lus par l'API du support |
| TM-17 | TM- | à écrire (étape 5) | Mesures en charge du planificateur d'ancrage : débit de points, journaux par instance, taille de la file en régime de panne (CT-5 §15) |
| TM-18 | TM- | à écrire (étape 5) | AN-26 : numéros de série du serveur RFC 3161 interne strictement croissants à travers un redémarrage |
| TM-19 | TM- | à écrire (étape 5) | AN-24 : précision déclarée (`accuracy`) d'au plus 1 s dans chaque jeton émis par le serveur interne ; écart d'horloge journalisé |
| TM-20 | TM- | exécutable | EX-7.18 de CT-7 : les six exigences de parité de l'attestation de périmètre, constatées sur tous les vecteurs |
| TM-21 | TM- | à écrire (étape 7) | EX-7.1 de CT-8 : installation rapide IR-1 à IR-8 en 900 s au plus, pas par pas, par une personne extérieure |
| TM-22 | TM- | à écrire (étape 7) | EX-8.1 de CT-8 : installation complète IC-1 à IC-18, durée totale sous 480 min (cible 450 min), pas par pas, attente de clôture relevée à part |
| TM-23 | TM- | à écrire (étape 7) | EX-8.1 de CT-8 : nombre d'informations absentes de CT-8 dont l'ingénieur a eu besoin (cible : zéro) |
| TM-24 | TM- | à écrire (étape 7) | Taille des images téléchargées à l'installation rapide (CT-8 §7.2, IR-6), sans cible |
| TM-25 | TM- | à écrire (étape 8) | EX-13.1 point 7 de CT-8 : temps d'un réviseur extérieur, de la réception du paquet au résultat, moins de 30 minutes la première fois |
| TM-26 | TM- | à écrire (étape 7) | EX-3.9 de CT-8 : le compagnon pose les attributs `a` et `i` toutes les 60 secondes au plus |
| TM-27 | TM- | à écrire (étape 7) | CT-8 §3.5 : durée de vie DNS du nom du répartiteur d'au plus 30 secondes |
| TM-28 | TM- | à écrire (étape 7) | EX-3.13 de CT-8 : égalité des condensés de deux constructions indépendantes de chaque image, du binaire du vérificateur et de la console |
| TM-29 | TM- | à écrire (étape 7) | EX-6.2 de CT-8 : seuils « cible » du contrôle préalable (IP-2 processeurs et mémoire, IP-3 espace libre) confrontés à la consommation observée |
| TM-30 | TM- | à écrire (étape 5) | Coefficient `b_ots` de CT-8 §9.2 : octets d'une preuve OpenTimestamps mise à niveau (défaut 233 en attente) |
| TM-31 | TM- | exécutable | Coefficient `b_cap` de CT-8 §9.2 : octets de la capture d'une transaction dans un bloc plein (CT-4 §9.2 : non mesuré) |
| TM-32 | TM- | à écrire (étape 3) | Coefficient `blocs_par_s` de CT-8 §9.2 sur l'instance de production du registre (réseau de développement : 1,10 le 2026-10-25) |
| TM-33 | TM- | à écrire (étape 7) | Coefficients sans valeur par défaut de CT-8 §9.2 : `f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl` (hypothèses de 9.5 jusqu'à la mesure) |
| TM-34 | TM- | à écrire (étape 7) | Seuils d'alerte « cible » de la supervision de CT-8 §10 : distribution des métriques en fonctionnement nominal et dans chaque scénario de runbook |
| TM-35 | TM- | à écrire (étape 7) | Seuil `<M>` de la mempool du nœud relais (CT-8 §10.6) : moitié de `-txpool-max-pending`, confronté à la file observée |
| TM-36 | TM- | à écrire (étape 7) | Durées des runbooks RB-1 à RB-8 de CT-8 (aucune n'est mesurée), rejoués sur la démonstration de référence |
| TM-37 | TM- | à écrire (étape 7) | EX-11.5 de CT-8 : RPO et RTO par composant, et cadence de sauvegarde de l'état du service d'approbation (15 min), mesurés par des exercices de restauration |
| TM-38 | TM- | à écrire (étape 8) | Mode observation (CT-8 §12.2) : latence ajoutée et durée d'écriture, cibles de CT-2 §16.1, par paire avec et sans l'enregistreur |
| TM-39 | TM- | à écrire (étape 7) | EX-11.19 de CT-8 : disponibilité et format du journal d'accès aux objets chez chaque fournisseur de support WORM |
| TM-40 | TM- | à écrire (étape 7) | IP-5 de CT-8 : ordre des champs de `chronyc -c tracking` relevé sur chrony 4.6 |
| TM-41 | TM- | à écrire (étape 5) | Fenêtre d'ordre observée `W_ordre` : délai entre un événement et l'inclusion au registre du premier point qui l'engage (CT-5 §3.3 : 60 s + d_registre) |
| TM-42 | TM- | à écrire (étape 5) | Fenêtre de réécriture pour la date, observée : `rewrite_window_end − ts` du premier point contresigné qui engage l'événement ; critère de la porte 2 : au plus 5 minutes |
| TM-43 | TM- | à écrire (étape 8) | EX-19.1 de CT-2 : la démonstration de référence se déroule en moins de deux minutes, temps mesuré et imprimé par `verificateur` |
| TR-1 | TR- | à écrire (étape 8) | CT-3 annexe A.5 : trois relecteurs (approbateur, auditeur, développeur) tirent la même décision sur dix cas d'une politique |
| TR-2 | TR- | à écrire (étape 8) | CT-3 annexe A.11 (EX-A.17) : lecture de la console par un approbateur et un développeur intégrateur, jugée par un troisième relecteur |
| TR-3 | TR- | à écrire (étape 8) | CT-4 §7.12 : un relecteur qui n'a que la spécification crée un client, ancre une racine et clôt une période sur le réseau de développement ; une seconde personne rejoue `verifier` |
| TR-4 | TR- | à écrire (étape 8) | CT-5 §1 : un relecteur qui n'a que CT-5 et CT-1 §9 à §11 dit la cadence des points, ce qu'un point prouve et ne prouve pas, la fenêtre de réécriture, le coût pour un prix unitaire donné et la conduite si le prestataire est injoignable |
| TR-5 | TR- | à écrire (étape 8) | CT-5 §1 et CT-6 §7.9 : un second relecteur qui n'a que CT-6 §7 (révisée) dit ce que le verdict prouve de nouveau avec un point de contrôle, et ce qu'il ne prouve toujours pas |
| TR-6 | TR- | à écrire (étape 8) | CT-7 EX-9.1 : un responsable de la sécurité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à six scénarios d'attaque par la réponse, la détection et le risque résiduel |
| TR-7 | TR- | à écrire (étape 8) | CT-7 EX-9.2 et EX-9.3 : un responsable de la conformité qui n'a que CT-7 sans la section 9 ni l'annexe A.15 répond à trois questions sur cinq passages, puis à la sixième question |
| TR-8 | TR- | à écrire (étape 8) | CT-7 EX-9.4 et EX-9.5 : un administrateur du client qui n'a lu que la section 7 répond à six questions sur l'attestation de périmètre |
| TR-9 | TR- | à écrire (étape 8) | CT-8 §14 épreuve (a), EX-14.1 à EX-14.5 : un ingénieur d'exploitation extérieur, avec CT-8 sans la section 14 ni l'annexe A, décrit les installations, dimensionne un cas et traite trois incidents |
| TR-10 | TR- | à écrire (étape 8) | CT-8 §14 épreuve (b), EX-14.6 à EX-14.10 : un réviseur extérieur, avec la seule section 13 et un poste sans réseau, vérifie deux paquets réviseurs en une commande et dit ce que le résultat prouve |
| TR-11 | TR- | à écrire (étape 8) | CT-8 §14 épreuve (c), EX-14.11 et EX-14.12 : un administrateur du client qui n'a lu que la section 12 répond à cinq questions sur le mode observation |
| TR-12 | TR- | à écrire (étape 8) | Rejeu complet sur machine vierge : une personne extérieure, avec la seule documentation publiée, installe, régénère les vecteurs, exécute les tests et les vérificateurs, et vérifie un dossier et un paquet |
| TR-13 | TR- | à écrire (étape 8) | CT-9 épreuve (a) : un testeur qui n'a que CT-9 et la spécification visée écrit, pour cinq entrées « à écrire » tirées au sort, les préconditions, les étapes et l'oracle en code ou pseudo-code exécutable, sans contredire le catalogue |
| TR-14 | TR- | à écrire (étape 8) | CT-9 épreuve (b) : un relecteur de la porte 2 qui n'a que CT-9 dit ce que le passage de la porte 2 prouve et ne prouve pas, et quel critère du plan chaque famille de tests sert |
| TR-15 | TR- | à écrire (étape 8) | CT-9 épreuve (c) : un développeur qui n'a que CT-9 ajoute au catalogue un test pour une exigence donnée en suivant les seules règles de CT-9, et l'outil de couverture l'accepte |
| TQ-1 | TQ- | à écrire (étape 8) | Revue de code de l'enregistreur : frontal MCP, passerelle, SDK et ingestion, écrivain et stockage, WORM, clés (CT-7 §3.2 ; CT-2 §18) |
| TQ-2 | TQ- | à écrire (étape 8) | Revue de code du service d'approbation et de la console (CT-7 §3.2 `approbation_console` ; CT-3 §14) |
| TQ-3 | TQ- | à écrire (étape 8) | Revue de code du registre et de l'exploitant : contrats, outil de référence, image du nœud, publication (CT-7 §3.2 `registre`, `exploitant` ; CT-4 §12) |
| TQ-4 | TQ- | à écrire (étape 8) | Revue de code du composant d'ancrage (CT-7 §3.2 `ancrage` ; CT-5 §13) |
| TQ-5 | TQ- | à écrire (étape 8) | Revue de code du vérificateur et indépendance des vérificateurs Go (CT-7 §3.2 `verificateur` ; CT-6 §15) |
| TQ-6 | TQ- | à écrire (étape 8) | Revue des fichiers de déploiement et de la configuration de l'administrateur du client (CT-7 §3.2 `administrateur_client`, `reseau` ; CT-8 §3, §5) |
| TQ-7 | TQ- | à écrire (étape 8) | Inventaire des clés et des secrets à jour : chaque clé ou secret introduit par une révision a sa ligne CLE- (CT-7 §4.1) |
| TQ-8 | TQ- | à écrire (étape 7) | Revue de la chaîne de construction et de publication des images : version publiée malveillante (RA-22, CT-8 §3.6) |

## `couverture.json`

Sortie de l'outil de couverture (`node scripts/tests/couverture.mjs --json`,
forme `rapport_couverture`) sur le dépôt et ce catalogue : verdict `reussi` ;
2332 identifiants définis par CT-1 à CT-8, 2193 couverts par une entrée, 139 par
une justification NC-, 0 non couvert(s) ; 98 menaces sur 98 avec un TA- ; 117
occurrences de « CT-9 » et 117 lignes TC- ; 208 entrées exécutables citant 400
titres ou étapes, 0 absent(s) ; 15 tables du texte comparées, 0 différence(s).

## `index-ta-par-menace.json`

Pour chaque menace MN-1 à MN-98 de `spec/vecteurs/ct-7/menaces.json` : son TA-,
son état (`executable` ou `a_ecrire`) et les scénarios TA-99 à TA-103 qui le
composent (EX-A.13).

## `cas/`

Chaque fichier est un catalogue réduit à une entrée ; `attendu.json` nomme la
définition du schéma (`racine`), le verdict attendu d'ajv (`valide` ou
`invalide`) et le mot-clé fautif attendu dans la première erreur (EX-A.3).

| Fichier | Attendu | Mot-clé |
|---|---|---|
| `cas/valide-minimal.json` | valide | — |
| `cas/valide-ta.json` | valide | — |
| `cas/invalide-executable-sans-titre.json` | invalide | `anyOf` |
| `cas/invalide-a-ecrire-sans-etape.json` | invalide | `required` |
| `cas/invalide-ta-sans-adversarial.json` | invalide | `required` |
| `cas/invalide-identifiant-sans-specification.json` | invalide | `pattern` |
| `cas/invalide-tm-mesure-inventee.json` | invalide | `type` |
| `cas/invalide-ta-titre-vide.json` | invalide | `minLength` |
| `cas/invalide-ta-complement-sans-etape.json` | invalide | `required` |
| `cas/invalide-ta-prefixe-test.json` | invalide | `pattern` |
| `cas/invalide-ta-scenario-sans-composition.json` | invalide | `required` |

## `mesures/`

Rapports de mesure de la version 0.1 (`$defs/rapport_mesure`, CT-9 §11.3,
EX-11.13) : le rapport vide (chaque ligne porte sa cible et `null` partout
ailleurs, `counts_for_targets` vrai) et le rapport sur les vecteurs
(`counts_for_targets` faux : 9 tailles de ligne du segment de la démonstration
de CT-2 recalculées à la génération, moyenne 1588,11 octets, ligne de l'annexe A
de 2 465 octets, constat de cadence). Les rapports des campagnes de la porte 2
s'écrivent à côté, jamais par le générateur (EX-11.11). `cas/cas.json` nomme
chaque cas, sa définition, son attendu pour ajv et la raison.

| Fichier | Attendu | Raison |
|---|---|---|
| `mesures/rapport-2026-11-01-vide.json` | valid | rapport vide de la version 0.1 |
| `mesures/rapport-2026-11-01-vecteurs.json` | valid | relevés sur les vecteurs publiés |
| `mesures/cas/valide-vide.json` | valid | Rapport vide de la version 0.1 : cibles présentes, null partout ailleurs, `counts_for_targets` vrai sur le système de référence. |
| `mesures/cas/valide-vecteurs.json` | valid | Relevés sur les vecteurs publiés : hors système de référence, `counts_for_targets` faux, chaque ligne exclue par `vecteurs_seulement`. |
| `mesures/cas/invalide-met-sans-valeur.json` | invalid | `met` booléen sans aucune valeur (`value`, `p50`, `p99`, `max`, `text_value`) : refusé. |
| `mesures/cas/invalide-compte-hors-reference.json` | invalid | `system.reference` faux avec `counts_for_targets` vrai : une mesure hors du système de référence ne compte pas pour les cibles. |
| `mesures/cas/invalide-fsync-desactive-compte.json` | invalid | `disk.fsync` faux avec `counts_for_targets` vrai : refusé (CT-2 EX-16.3). |
| `mesures/cas/invalide-disque-memoire-compte.json` | invalid | `disk.type` `memoire` avec `counts_for_targets` vrai : refusé. |
| `mesures/cas/invalide-met-sans-compter.json` | invalid | Rapport qui ne compte pas pour les cibles avec une ligne `met` booléenne et sans `excluded_reason` : refusé. |
| `mesures/cas/invalide-unite-inconnue.json` | invalid | Unité hors de l'énumération (`secondes` au lieu de `s`) : aucune conversion dans un rapport. |
| `mesures/cas/invalide-percentile-autre-methode.json` | invalid | `percentile_method` autre que `plus_proche_rang` : refusé (EX-11.3). |
| `mesures/cas/invalide-machine-incomplete.json` | invalid | Membre `kernel` absent de `system` : la machine est décrite en entier ou le rapport est refusé. |
| `mesures/cas/invalide-test-id-autre-famille.json` | invalid | `test_id` d'une autre famille (TU-1) : une ligne de mesure se rattache à un TM-. |

## `consignations/`

Gabarit de consignation d'une épreuve à l'aveugle (`$defs/consignation_rejeu`,
CT-9 §12.1, EX-12.4) pour TR-10 : SHA-256 à zéro, `duration_s` null, verdict
d'exemple ; les consignations réelles sont ajoutées par l'examinateur
(`<TR-n>-<AAAA-MM-JJ>-<P-nn>.json`), jamais par le générateur. `cas/cas.json`
nomme chaque cas, sa définition, son attendu pour ajv et la raison.

| Fichier | Attendu | Raison |
|---|---|---|
| `consignations/gabarit-TR-10.json` | valid | gabarit de TR-10 |
| `consignations/cas/valide-gabarit.json` | valid | Gabarit de TR-10 : pseudonymes, juge indépendant, matériel avec SHA-256 de gabarit, verdict réussi avec chaque élément présent. |
| `consignations/cas/invalide-reussi-element-absent.json` | invalid | Verdict `reussi` avec un élément de grille absent : refusé (EX-12.6). |
| `consignations/cas/invalide-reussi-disqualifiant.json` | invalid | Verdict `reussi` avec une affirmation disqualifiante : refusé (EX-12.6). |
| `consignations/cas/invalide-juge-non-independant.json` | invalid | Juge qui a aidé le participant (`independent` faux) : refusé (EX-12.5). |
| `consignations/cas/invalide-nom-de-personne.json` | invalid | Participant désigné par un nom au lieu d'un pseudonyme `P-nn` : refusé (EX-12.1). |
| `consignations/cas/invalide-sans-materiel.json` | invalid | Aucun matériel remis consigné : refusé (EX-12.2). |

## Consignes et grilles des épreuves (`acceptation-*`)

Consignes remises aux participants des épreuves que leur spécification ne dote
d'aucune grille (TR-4, TR-5) et des trois épreuves de CT-9 (TR-13 à TR-15), et
grilles à part (`grille-acceptation`, `$defs/grille_acceptation` ; EX-12.7,
EX-A.16). Une grille n'est jamais remise au participant ni recopiée dans sa
consigne ; `test/plan-de-tests.test.js` vérifie qu'aucune consigne ne contient
un élément de sa grille. La grille de la porte 2 est produite depuis la section
14 du texte et la table des niveaux (EX-15.2).

| Fichier | Épreuve | Contenu |
|---|---|---|
| `acceptation-ancrage-attendu.json` | TR-4 | grille : 5 questions, 18 éléments, 1 affirmation(s) disqualifiante(s) |
| `acceptation-verdict-point-attendu.json` | TR-5 | grille : 4 questions, 8 éléments, 2 affirmation(s) disqualifiante(s) |
| `acceptation-porte-2-attendu.json` | TR-14 | grille : 3 questions, 24 éléments, 3 affirmation(s) disqualifiante(s) |
| `acceptation-ancrage/consigne.md` | TR-4 | consigne remise au participant |
| `acceptation-verdict-point/consigne.md` | TR-5 | consigne remise au participant |
| `acceptation-plan/consigne.md` | TR-13, TR-15 | consigne remise au participant |
| `acceptation-porte-2/consigne.md` | TR-14 | consigne remise au participant |

## `extraits/`

Extraits des spécifications remis aux participants (EX-12.2), découpés par
sections de niveau 2 et 3 du texte du commit éprouvé, hors blocs de code, sans
autre modification ; `SHA256SUMS` donne le condensé de chaque extrait, consigné
à la remise.

| Fichier | Épreuves | Contenu |
|---|---|---|
| `extraits/CT-7-sans-9-A15.md` | TR-6, TR-7 | CT-7 sans la section 9 ni l'annexe A.15 |
| `extraits/CT-8-sans-14-A.md` | TR-9 | CT-8 sans la section 14 ni l'annexe A |
| `extraits/CT-8-13.md` | TR-10 | CT-8, section 13 seule |
| `extraits/CT-8-12.md` | TR-11 | CT-8, section 12 seule |
| `extraits/CT-7-7.md` | TR-8 | CT-7, section 7 seule |
| `extraits/CT-9-sans-15.md` | TR-13, TR-14, TR-15 | CT-9 sans la section 15 |
| `extraits/SHA256SUMS` | toutes | SHA-256 de chaque extrait |
