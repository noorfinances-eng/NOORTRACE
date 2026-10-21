# NOORTRACE — architecture cible

Version 0.2, 20 octobre 2026. Document de conception, pas d'implémentation.

## Principe

Un journal n'a de valeur probatoire que si trois acteurs ne peuvent pas le réécrire :
l'agent, l'opérateur de l'agent, et le fournisseur du journal. NOORTRACE sépare donc
trois rôles.

| Rôle | Qui | Ce qu'il peut faire | Ce qu'il ne peut pas faire |
|---|---|---|---|
| Enregistreur | Composant déployé chez le client | Capturer, chaîner, signer les événements | Être lu ou modifié par l'agent |
| Registre et approbations | NOORTRACE, sur NOORCHAIN | Enregistrer les lots d'empreintes et les décisions humaines | Modifier un événement déjà chaîné |
| Ancre de confiance | Prestataire qualifié et registre public | Horodater les racines de lots | Rien d'autre : il ne voit que des empreintes |

## Flux

1. **Capture.** L'enregistreur s'insère entre l'agent et ses outils, comme proxy MCP
   ou comme SDK dans le runtime. Chaque appel d'outil, chaque lecture ou écriture de
   données, chaque sortie produit un événement.
2. **Chaînage.** Chaque événement porte l'empreinte du précédent et une signature
   de l'enregistreur. Le journal est en ajout seul, sur un volume séparé de celui
   de l'agent, conformément aux recommandations du PFPDT sur la journalisation.
3. **Approbation.** Les actions marquées sensibles par la politique du client sont
   suspendues jusqu'à décision d'un approbateur humain. La décision, son auteur, son
   instant et son motif deviennent des événements du même journal. Les jeux
   d'approbateurs, repris des contrats de curateurs de NOORCHAIN, fournissent ce
   mécanisme : bornés, tracés, contestables.
4. **Ancrage.** Toutes les heures, la racine de Merkle des événements de la période
   est horodatée par un prestataire de confiance qualifié ZertES et eIDAS, puis
   ancrée sur un registre public gratuit. Seule la racine quitte le client.
5. **Dossier de preuve.** À la demande, pour un incident, une revue ou une requête
   du régulateur, le client exporte les événements concernés, les preuves d'inclusion
   et les jetons d'horodatage.
6. **Vérification.** Un vérificateur en ligne de commande, publié en source ouverte,
   recalcule la chaîne, contrôle les preuves d'inclusion, valide les jetons
   d'horodatage contre le certificat du prestataire et la preuve d'ancrage public.
   Il fonctionne hors ligne et sans accès à NOORTRACE.

Le détail de chaque étape est dans la section « Chaîne de traitement ».

## Modèle d'événement

Huit champs, alignés sur le schéma proposé par le papier Agent Flight Recorder
([arXiv 2609.01931](https://arxiv.org/pdf/2609.01931)) :

| Champ | Contenu |
|---|---|
| Intention | Ce que l'agent déclare vouloir faire et pourquoi |
| Évaluation de politique | Règle appliquée, résultat : autorisé, à approuver, refusé |
| Approbation humaine | Décision, approbateur, instant, motif, le cas échéant |
| Exécution | Outil appelé, paramètres, réponse, durée |
| Effets | Ressources lues, écrites, supprimées, envoyées |
| Provenance du contexte | Documents, données et mémoire utilisés |
| Provenance du code | Version du modèle, du prompt système, de la politique, de l'enregistreur |
| Provenance de la délégation | Qui a lancé l'agent, pour le compte de qui, avec quels droits |

Format d'export : spans OpenTelemetry GenAI pour l'interopérabilité, reçus SCITT
(RFC 9943) pour les preuves d'inclusion, compatibilité visée avec le projet IETF
« agent audit trail ». Aucun format propriétaire.

La forme normative des événements, du manifeste et du dossier, avec ses vecteurs de
test et deux implémentations indépendantes, est la spécification CT-1 :
`spec/CT-1-evenements-et-formats.md`.

## Chaîne de traitement

### Capture : où l'enregistreur se place

Un agent n'agit que de deux façons observables : il échange avec un modèle, et il
appelle des outils. La capture se fait aux deux frontières, hors du processus de
l'agent. L'étude « LLM Agents Can Easily Tamper With Their Own Traces »
([arXiv 2609.30266](https://arxiv.org/abs/2609.30266)) montre que, dans tous les
harnais testés sauf un, l'agent peut effacer ses propres traces : une capture dans le
processus de l'agent n'a pas de valeur probatoire.

- **Frontière des outils : un serveur MCP mandataire.** Les agents d'entreprise
  appellent leurs outils par le protocole MCP, qui est du JSON-RPC 2.0. Chaque action
  est un message `tools/call` portant le nom de l'outil et ses arguments ; la réponse
  porte le contenu et un drapeau d'erreur. L'enregistreur est lui-même un serveur
  MCP : l'hôte de l'agent est configuré pour ne parler qu'à lui, et lui seul se
  connecte aux vrais serveurs du client, ERP, CRM, messagerie, fichiers, bases de
  données, dont il agrège les outils et relaie les appels. Transports stdio et HTTP.
  Le pare-feu du client n'autorise que le mandataire à joindre les serveurs d'outils,
  donc l'agent ne peut pas le contourner.
- **Frontière du modèle : le proxy de sortie du client.** Les appels à l'API du
  modèle sortent par un proxy HTTPS d'entreprise avec interception TLS, comme tout
  flux surveillé. L'enregistreur y lit les messages envoyés, le texte produit, les
  blocs d'appel d'outil et leurs résultats, la version du modèle et le prompt
  système. L'intention de l'événement est le texte de l'assistant qui précède l'appel
  d'outil, quand il existe.
- **Cas restant : un SDK.** Pour un agent sans MCP et avec modèle local, une
  bibliothèque enveloppe l'exécution des outils. Elle tourne dans le processus de
  l'agent, donc elle est plus faible ; elle n'est acceptée que combinée au proxy
  réseau.

### Journal : comment un événement est écrit

Chaque appel vu par le mandataire devient un événement JSON à huit champs, dans la
forme normative de `spec/CT-1-evenements-et-formats.md`. Exemple abrégé pour un
paiement de sinistre approuvé, l'événement 4 de l'exemple de référence de la
spécification, valeurs complètes dans celle-ci :

```json
{
  "version": 0,
  "seq": 4,
  "ts": "2026-11-03T13:52:41.090Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832",
  "delegation": {"launched_by": "u.martin@assureur-demo.example", "on_behalf_of": "service-sinistres", "scope": "sinistres:lecture,paiement", "run_id": "run-2026-11-03-0142"},
  "code": {"model": "fournisseur/modele@2026-09", "prompt_version": "0xb715…6b58", "policy_version": "2026-11-01", "recorder": "0.1.0"},
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {"rule": "paiement > 5000 CHF", "decision": "a_approuver", "ticket": "apr-1192", "redaction": "pii-v1"},
  "approval": {"decision": "approuve", "ticket": "apr-1192", "request_hash": "0xdd3b…fce0", "threshold": {"required": 2, "size": 3}, "approvers": ["0x7099…79c8", "0x3c44…93bc"], "signatures": ["0x9b56…a01b", "0xed53…151b"], "at": "2026-11-03T13:52:40.511Z", "reason": "Pièces validées"},
  "execution": {"tool": "sap.payments.create", "arguments": {"sha256": "0x0fb2…aaf9", "length": 96, "redacted": true}, "status": "executee", "result": {"sha256": "0x8bbf…9624", "length": 85, "redacted": false}, "duration_ms": 412, "is_error": false},
  "effects": [{"system": "SAP", "action": "ecriture", "object": "PAY-2026-55120", "amount": "7400.00", "currency": "CHF"}],
  "context": [{"kind": "document", "sha256": "0x…", "length": 48213, "redacted": false}],
  "hash": "0x…",
  "sig": "0x…"
}
```

Mécanique :

- L'événement est mis en forme canonique JCS (RFC 8785), puis haché en SHA-256. Le
  champ `prev_hash` reprend le hachage de l'événement précédent et `seq` est
  strictement croissant. Toute suppression, insertion ou modification casse la chaîne.
- L'enregistreur signe chaque événement en Ed25519 avec une clé conservée dans le HSM,
  le KMS ou la puce TPM du client. Sa clé publique est enregistrée dans le registre au
  moment de l'onboarding ; une rotation de clé est elle-même un événement signé par
  l'ancienne clé et la nouvelle.
- Les arguments et résultats complets sont stockés à côté, chez le client ; seuls
  leurs hachages entrent dans l'événement. La rédaction des champs sensibles se fait
  avant hachage, selon la politique du client, et la règle appliquée est journalisée.
- Le journal est en ajout seul : segments de fichiers scellés plus une base locale
  pour la recherche. Il ne quitte jamais le périmètre du client.
- Toutes les heures, l'enregistreur construit un arbre de Merkle sur les événements
  de l'heure, selon le schéma de RFC 6962, et obtient une racine R de 32 octets. Un
  manifeste de période, qui porte R, le premier et le dernier `seq`, le nombre
  d'événements, l'empreinte du manifeste précédent et un nonce, est signé par
  l'enregistreur. R est la seule donnée qui sort.

### Approbation : avant l'action, pas après

La politique est évaluée sur chaque `tools/call` avant relais. Une règle est un outil
plus des prédicats sur ses arguments, par exemple `sap.payments.create` et
`montant > 5000 CHF`. Trois sorties : autorisé et journalisé, à approuver, refusé.

Quand la sortie est « à approuver » :

1. Le mandataire ne transmet pas l'appel. Il crée un ticket, le journalise, et
   notifie les approbateurs du client dans la console reprise du hub.
2. Chaque approbateur signe sa décision avec sa clé, en EIP-191, comme les curateurs
   de NOORCHAIN signent aujourd'hui. Le seuil, par exemple deux sur trois, est celui
   du jeu d'approbateurs du client dans le contrat CuratorSet.
3. La décision signée devient un événement du journal, puis l'appel est relayé ou
   refusé. Délai écoulé sans décision : refus, journalisé.

MCP n'a pas d'état « en attente » pour un appel d'outil. Le mandataire retient la
réponse jusqu'à la décision ou jusqu'au délai de l'hôte ; au-delà, il renvoie une
erreur qui porte le numéro de ticket, et l'agent réessaie une fois la décision prise.
Le choix entre les deux comportements est une décision ouverte, à régler au prototype.

### Ancrage : trois ancres indépendantes pour une racine

Chaque heure, la racine R reçoit trois ancres :

1. **Registre.** Une transaction vers l'instance dédiée de noorcore appelle la
   fonction `anchor` du contrat AttestationRegistry avec R comme empreinte, un type de
   lot, l'adresse de l'enregistreur et sa signature. Le contrat émet l'événement
   `Anchored` ; `lookup` rend l'enregistrement à quiconque interroge le RPC d'un
   validateur, et la méthode `noor_getCommitCertificate` rend le certificat de commit
   du bloc, signé par un quorum des validateurs, que le dossier emporte et que le
   vérificateur contrôle hors ligne. Le mode suiveur de noorcore est un relais RPC :
   il ne réplique ni blocs ni état, et ne donne pas de copie indépendante. La
   clôture de période signée par les approbateurs passe par `submitPeriod` du
   contrat PeriodRegistry, dérivé de PoSSRegistry sans le hachage des paiements, avec
   continuité par journal : chaque période commence où la précédente finit, en temps
   et en numéro de séquence. Les clés d'enregistreur sont inscrites par organisation
   dans RecorderRegistry, sous signatures des approbateurs au seuil. Le registre donne l'ordre et la
   consultation, pas la preuve.
2. **Horodatage qualifié.** Une requête RFC 3161 contenant SHA-256 de R et un nonce
   part vers le prestataire reconnu. La réponse est un jeton CMS signé par lui, avec
   l'heure UTC, l'exactitude et son certificat. Il se vérifie avec
   `openssl ts -verify` contre la chaîne de certificats du prestataire, sans NOORTRACE.
3. **Ancrage public.** `ots stamp` sur R produit un fichier `.ots`. Les calendriers
   OpenTimestamps agrègent et inscrivent dans Bitcoin ; `ots upgrade` complète la
   preuve après confirmation. La vérification se fait avec les en-têtes de blocs
   Bitcoin, depuis un nœud ou une source d'en-têtes.

En option, un serveur RFC 3161 interne, non qualifié, contresigne la chaîne toutes les
minutes pour l'ordre fin entre deux ancres qualifiées. Il figure dans le dossier comme
indice, étiqueté non qualifié, jamais comme preuve.

Ce que les tiers voient : 32 octets par heure. Jamais un argument, jamais un document.

### Dossier et vérification

Le dossier remis pour un événement contient : l'événement, ses deux voisins
complets, dont les hachages se recalculent, le chemin de Merkle jusqu'à R, R et le manifeste de période, le jeton
RFC 3161, la preuve `.ots`, le reçu de la transaction du registre avec le certificat
de commit de son bloc et le jeu de validateurs de ce bloc, les événements
d'approbation liés avec leurs signatures, et les clés publiques et certificats
nécessaires. Un événement se prouve seul, sans révéler les autres.

Le vérificateur, binaire autonome sans réseau, refait dans l'ordre :

1. hachage canonique de l'événement et égalité avec `hash` ;
2. continuité de la chaîne avec les voisins fournis ;
3. recalcul du chemin de Merkle jusqu'à R ;
4. signature du jeton RFC 3161 contre la chaîne de certificats du prestataire, et
   égalité entre l'empreinte du jeton et SHA-256 de R ;
5. preuve OpenTimestamps contre les en-têtes de blocs Bitcoin ;
6. signature Ed25519 de l'enregistreur sur l'événement ;
7. signatures des approbateurs et respect du seuil ;
8. inclusion de la transaction du registre dans un bloc dont le certificat de commit
   est signé par un quorum du jeu de validateurs fourni, et égalité entre le hachage
   du bloc et celui du certificat.

Sa sortie tient en une ligne : cet événement existait sous cette forme avant telle
heure UTC selon tel prestataire, et avant tel bloc Bitcoin, il a été approuvé par
les personnes nommées, et son ancre est dans un bloc que les validateurs nommés ont
signé.

## Ancrage et droit de la preuve

- L'horodatage électronique qualifié porte la présomption légale d'exactitude de la
  date et d'intégrité (art. 41(2) eIDAS). En Suisse, la ZertES définit l'horodatage
  qualifié par un prestataire reconnu. Swisscom Trust Services est le seul prestataire
  identifié sous les deux régimes.
- NOORTRACE n'opère pas lui-même l'horodatage qualifié. En Suisse, un fournisseur
  reconnu doit pouvoir délivrer et gérer des certificats qualifiés, employer du
  personnel qualifié, disposer de garanties financières et d'une assurance d'au moins
  2 millions de francs par cas et 8 millions par an (ZertES art. 3, VZertES art. 2), et
  obtenir la reconnaissance d'un organisme accrédité, aujourd'hui KPMG AG seul. Dans
  l'UE, il faut une notification à l'autorité de contrôle avec rapport d'évaluation de
  conformité et un audit à ses frais au moins tous les 24 mois (eIDAS art. 20 et 21).
  Surtout, la valeur de la preuve repose sur un tiers qui ne contrôle ni l'horloge ni
  le sceau : un horodatage délivré par le fournisseur de la preuve recréerait le
  problème que le produit supprime.
- L'ancrage sur un registre public est complémentaire : il permet la vérification sans
  intermédiaire mais ne porte pas de présomption légale.
- NOORCHAIN, opérée par le fournisseur, ne peut pas servir d'ancre de confiance. Elle
  tient le registre des lots et des approbations, et doit rester substituable.
- La procédure est documentée pour satisfaire l'art. 9 GeBüV : signatures, horodatage,
  conservation des journaux et des logs du système.

## Instance dédiée

Décision du 20 octobre 2026 : NOORTRACE tourne sur une instance dédiée de noorcore,
distincte de la chaîne 2123 du PoSS.

- Identifiant de chaîne propre, validateurs propres, aucun contrat de jeton ni de
  récompense déployé.
- Un seul registre pour tous les clients ; chaque client est une organisation avec
  son jeu d'approbateurs. Aucune donnée métier sur la chaîne, seulement des racines.
- Les validateurs sont ouverts aux partenaires : un intégrateur ou un cabinet d'audit
  qui opère un validateur rend le registre moins dépendant du fournisseur. C'est
  aussi la seule copie complète du registre hors de nos mains.
- Un incident ou une mise à jour du PoSS ne touche pas les clients NOORTRACE, et la
  description du périmètre pour l'inventaire des externalisations reste simple.
- Pour le pilote, une instance de développement suffit ; la chaîne de production est
  arrêtée après le pilote.

Terminologie : « approbateur » désigne le rôle que les contrats de NOORCHAIN nomment
curateur. Le mécanisme est repris, le mot et la fonction sociale ne le sont pas.

## Déploiement

- Enregistreur et journal chez le client : sur site, dans son tenant cloud ou chez un
  hébergeur suisse. Seules les racines de lots sortent.
- Prérequis réseau chez le client : les serveurs d'outils ne sont joignables que par
  le mandataire, et les appels à l'API du modèle passent par le proxy de sortie avec
  interception TLS.
- Registre et console NOORTRACE : hébergés en Suisse. Rétention probatoire visée :
  10 ans, alignée sur l'art. 958f CO et l'art. 18 du Règlement IA.
- Vérificateur : binaire autonome, sans réseau, publié avec son code et ses vecteurs
  de test.

## Modèle de menace

| Menace | Réponse |
|---|---|
| L'agent efface ou falsifie ses traces | Journal en ajout seul, hors de son contexte d'exécution, chaîné et signé |
| L'agent contourne l'enregistreur | Pare-feu : seuls le mandataire et le proxy de sortie joignent les outils et l'API du modèle |
| L'opérateur réécrit l'historique après coup | Racines horodatées par un tiers qualifié : toute réécriture casse les preuves d'inclusion |
| L'enregistreur lui-même est compromis | Clé en HSM, KMS ou TPM ; les ancres horaires bornent la fenêtre de réécriture ; contresignature interne à la minute en option |
| Le fournisseur NOORTRACE triche ou disparaît | Vérification possible sans lui ; registre substituable ; format ouvert |
| Le fournisseur sert une histoire falsifiée par son RPC | Certificat de commit du bloc vérifié hors ligne contre le jeu de validateurs ; validateurs partenaires en production |
| Manipulation de l'horloge | Temps issu du jeton d'horodatage qualifié, pas de l'hôte |
| Fuite de données via les empreintes | Seules des racines de Merkle sortent du périmètre du client |

## Ce qui est réutilisé de noorchain-core

| Dépôt noorchain-core | Usage |
|---|---|
| `contracts/poss/AttestationRegistry.sol` | Registre des racines de lots : `anchor`, `lookup`, `isAnchored` |
| `contracts/poss/CuratorSet.sol`, `CuratorSetRegistry.sol` | Jeux d'approbateurs par client, seuil, administration reprise par le client |
| `contracts/poss/PoSSRegistry.sol` | Modèle de PeriodRegistry, dérivé sans le champ des paiements, avec continuité par journal ; dans `contracts/` |
| `dapps/curators-hub` | Base de la console d'approbation et de revue, signature EIP-191, page de vérification |
| `docs/runbooks`, `ops/observability` | Exploitation du service |
| `core/` | Nœud du registre d'exploitation, inchangé |

Écrit, 21 octobre 2026 : la spécification CT-1 avec ses schémas, ses vecteurs, son
implémentation de référence et son vérificateur Go indépendant ; le vérificateur de
dossier ; les contrats du registre, PeriodRegistry, RecorderRegistry et
ThresholdSignatures, avec leurs tests ; l'instance de développement dédiée dans
`chain/` ; les scripts de déploiement et le parcours complet ; la méthode RPC
`noor_getCommitCertificate`, portée comme correctif sur noorcore, fourni hors dépôt public et déposé dans
`chain/patches/` à la construction,
et appliquée à la construction du binaire, et le vérificateur hors ligne des
certificats de commit. À écrire : le mandataire
MCP, le raccord au proxy de sortie, le schéma d'événements, le chaînage et l'arbre de
Merkle, les clients RFC 3161 et OpenTimestamps, le format du dossier, le vérificateur.

## Décisions ouvertes

1. Granularité : close par CT-1. Un événement par appel d'outil, par échange avec le
   modèle, par décision d'approbation ou par événement du journal sur lui-même ; un lot
   par heure UTC. Coût et latence restent à mesurer au prototype.
2. Gestion des clés de l'enregistreur chez le client : HSM, KMS ou TPM, choix par
   client selon ce qu'il possède déjà.
3. Politique de rédaction des paramètres sensibles avant hachage.
4. Comportement du mandataire pendant une approbation : réponse retenue ou erreur
   avec ticket, selon le délai de l'hôte.
5. Format d'export : close par CT-1, version 0 spécifiée avec ses vecteurs ; révision
   prévue après les trois premiers entretiens de réviseurs, en version 1.
6. Identifiant de la chaîne de production et premiers validateurs partenaires, après le pilote.
7. Mode observateur de noorcore : nœud non validateur qui rejoue les blocs et vérifie
   leurs certificats chez le client, pour une copie indépendante en lecture. Chantier
   de consensus et de réseau, à chiffrer sur le code de rattrapage BFT ; déclenché si
   un client ou un réviseur l'exige. Le mode suiveur actuel n'en tient pas lieu.
