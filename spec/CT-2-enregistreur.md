# CT-2 — Enregistreur

Version 0.3, 2026-10-23. Spécification normative, soumise à revue. Elle met
en œuvre la section
« Capture : où l'enregistreur se place » et la section « Journal : comment un
événement est écrit » de l'[architecture cible](../ARCHITECTURE.md), s'appuie
sur le format d'événement de [CT-1](CT-1-evenements-et-formats.md) sans le
modifier, et clôt les décisions ouvertes 2 (clés de l'enregistreur) et 3
(rédaction avant hachage) de l'architecture (section 20). La révision 0.3
l'aligne sur [CT-3](CT-3-approbations.md) (interface du service
d'approbation), retire les codes d'erreur de la plage que la révision MCP
`2026-07-28` dit héritée et borne le coût des motifs de rédaction ; la
section 0.4 dit ce qu'elle change.

## 0. En-tête, conventions, lecture

### 0.1 Conventions

Les mots DOIT, NE DOIT PAS, DEVRAIT et PEUT ont le sens de la RFC 2119, comme
dans CT-1. Les clés JSON sont en anglais ; les valeurs énumérées sont en
français, sans accent (`bloquant`, `passant`, `executee`, `lecture`,
`ecriture`), comme dans CT-1 et l'architecture.

Chaque règle normative porte un identifiant **EX-<section>.<n>** (par exemple
EX-4.3 : troisième règle de la section 4), stable, auquel le plan de tests
(CT-9) attache ses tests. Les identifiants de la version 0.1 sont numérotés
dans l'ordre du texte à l'intérieur de chaque section de premier niveau,
sous-sections comprises. Une règle ajoutée par une révision reçoit le numéro
qui suit le plus grand de sa section, quel que soit l'endroit où elle est
insérée (la version 0.2 ajoute ainsi EX-4.43 et suivants, la version 0.3
EX-4.49 et suivants) ; aucun numéro n'est jamais réattribué. Une règle
retirée garde son numéro, marqué « retiré ». Les règles ajoutées, modifiées
ou retirées par chaque révision sont listées en 0.4.

Les faits externes (révision du protocole MCP, formats d'API, variables des
SDK, comportement des mandataires et des pare-feu) viennent des digests de
recherche du lot CT-2, notes internes toutes relues le 2026-10-22 sur les pages
officielles ou les fichiers de code qu'elles citent. Chaque fait porte un
renvoi court (R1 à R9, suivi le plus souvent du numéro de question, de fait, de
point non vérifié, de conséquence ou de section, par exemple « R1 Q2 » ou « R7
F-25 » ; sans numéro, le renvoi vise la note entière) ; ces digests ne sont pas
publiés. La révision 0.3 s'appuie en outre sur une dixième note, **R10**
(politique des codes d'erreur de MCP, traitement des erreurs par les SDK et les
hôtes, motifs à retour arrière, exécution bornée dans Node.js), relue le
2026-10-23 sur ses sources primaires ; ses faits portent la forme « R10 F-2 »
et ses points non vérifiés « R10 NV-3 ». L'annexe C résout chaque renvoi : elle
donne l'objet du fait et la ou les sources primaires publiques consultées, avec
leur date de consultation, de sorte que le lecteur peut recouper le fait sans
le digest. Quand le texte nomme une page officielle, l'annexe C en donne l'URL
sous le renvoi qui l'accompagne ; certaines de ces URL figurent aussi dans le
texte. Ce qui n'a pas pu être vérifié est écrit comme tel, dans le texte comme
dans l'annexe C ; l'annexe C signale aussi ce que la note n'appuie sur aucune
page publique.

Les séquences « octet par octet » sont des listes numérotées où chaque pas nomme
ce qui est lu, écrit, haché ou envoyé, dans l'ordre réel d'exécution. Les
exemples JSON sont complets et valides ; ceux de l'annexe A sont calculés, pas
illustratifs : leurs octets, hachages et signatures se recalculent avec les
clés de test de CT-1 §13.

### 0.2 Ce que CT-2 suppose de CT-1

CT-2 produit des événements au format de CT-1 et rien d'autre. Elle suppose
acquis, sans les répéter :

| CT-1 | Ce que CT-2 en retient |
|---|---|
| §3 Conventions d'encodage | Hexadécimal `0x` minuscule, horodatages RFC 3339 UTC à la milliseconde, entiers sûrs, montants en chaînes, `null` pour les clés optionnelles sauf `media_type` et `value`. |
| §4 Forme canonique JCS v0 | Les structures hachées de CT-1 (événement, manifeste, valeurs en ligne) restent en JCS v0, entiers seulement. CT-2 introduit en plus le **JCS intégral** (RFC 8785 tel quel) pour les **pièces** (section 8) ; les deux ne se confondent jamais. |
| §5 Événement v0 | Les dix-sept clés, les huit champs, les quatre sortes réservées (E-3), les références `{ sha256, length, redacted[, media_type][, value] }`. CT-2 n'ajoute aucun type d'événement et aucune clé. |
| §5.4 Références et rédaction | « La pièce stockée est exactement ce qui a été haché » et « la rédaction se fait avant hachage » : CT-2 fixe comment une pièce est sérialisée (section 8) et comment elle est rédigée (section 10). |
| §6 Hachage et signature | `hash = SHA-256(P_H ‖ JCS_v0(E'))`, `sig = Ed25519(P_S ‖ JCS_v0(E'))`, Ed25519 pur, vérification sans cofacteur. L'enregistreur signe exactement ainsi ; la clé est décrite en section 11. |
| §7 Chaînage | `seq` sans trou, `prev_hash`, `ts` non décroissant : l'enregistreur est l'écrivain unique qui garantit ces invariants (sections 12 et 13). |
| §8 Rotation de clé | La rotation est un événement signé par l'ancienne clé et contresigné par la nouvelle ; CT-2 dit quand elle est déclenchée (sections 9 et 11). |
| §9 et §10 Merkle et manifeste | La clôture horaire est produite par l'enregistreur avec les mêmes octets que CT-1 ; CT-2 ne la redéfinit pas. |
| §11 Dossier | L'export du dossier est une fonction de l'enregistreur (CT-6 en fixe la ligne de commande) ; CT-2 fixe où sont les pièces que le client peut joindre. |
| §13 Clés et vecteurs | Les clés de test `rec-test-01`, `rec-test-02` et les comptes Hardhat 1 à 3 servent aussi aux vecteurs CT-2 (annexe B) et à l'annexe A. |

Les renvois que CT-1 fait à CT-2 trouvent ici leur réponse :

| Renvoi de CT-1 | Section de CT-2 |
|---|---|
| §5.2 `ts` : « la stratégie de l'enregistreur quand son horloge recule est du ressort de CT-2 » | 7.4 (règle) et 14 (seuil et comportement bloquant) |
| §5.3 `code.prompt_version` : prompt système « rédigé avant hachage si nécessaire (règle de CT-2) » | 5.5, 8.2 et 10 |
| §5.3 `execution.tool` : « nom de l'outil tel qu'annoncé par `tools/list` » | 4.3 |
| §5.3 `effects` : « déclarés par le mandataire à partir de la description de l'outil et de ses arguments (CT-2, CT-3) » | 7.2 |
| §5.4 : « comment une requête ou une réponse est sérialisée en octets avant hachage […] est fixé par CT-2 » | 8 |
| §14 : « le coût et la latence restent à mesurer en phase 2 (CT-2) » | 16 |
| §15 : « la sérialisation des pièces avant hachage et la rédaction (CT-2) », « la rédaction du prompt avant stockage, ou son remplacement par un identifiant de version nommé » | 8 et 10 |

### 0.3 Révision du protocole MCP de référence

La révision du protocole MCP en vigueur au 2026-10-22 est **2026-07-28** (page
« Versioning » de la spécification : « The current protocol version is
2026-07-28 », digest R1, Q1). Cette révision rend le protocole sans état :
elle supprime la poignée de main `initialize`/`notifications/initialized`,
l'en-tête `Mcp-Session-Id`, le flux HTTP GET, la reprise SSE, `ping`,
`logging/setLevel` et les requêtes du serveur vers le client, remplacés par des
métadonnées par requête dans `_meta`, par `server/discover`, par
`subscriptions/listen` et par le motif MRTR (changelog 2026-07-28, R1 Q1). Les
révisions `2025-11-25`, `2025-06-18` et `2025-03-26` sont dites « legacy » (à
poignée de main). La révision parlée par chaque hôte n'a pas été vérifiée ;
deux indices montrent que l'ère héritée reste en usage : la ligne de
maintenance du SDK TypeScript, `@modelcontextprotocol/sdk` 1.32.1, s'arrête à
`2025-11-25` (https://registry.npmjs.org/@modelcontextprotocol/sdk, R1 Q11),
et l'Inspector MCP démarre par défaut en ère héritée
(https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/protocol-eras).
La spécification nomme « dual-era » une implémentation qui gère les deux ères
(R1 Q2). L'enregistreur est dual-era (section 4.2).

La révision `2026-07-28` partage aussi la plage `-32000` à `-32099` que
JSON-RPC 2.0 laisse aux erreurs définies par l'implémentation : `-32000` à
`-32019` sont dits hérités (aucun code nouveau n'y est alloué, MUST NOT ;
une implémentation nouvelle ne les emploie pas, SHOULD NOT ; le récepteur ne
leur suppose aucun sens, MUST NOT, sauf `-32002`) ; `-32020` à `-32099` sont
réservés à la spécification ; un code nouveau est pris hors de `-32768` à
`-32000` (SHOULD) (page Overview, section « Error Codes », R10 F-2 à F-4).
La version 0.2 prenait ses codes dans `-32010` à `-32019` sur la foi du
journal des modifications de la révision, plus souple que le texte
normatif (R10 F-5, F-15). La version 0.3 prend les codes de l'enregistreur
hors de la plage réservée et rend les issues d'approbation comme des
résultats d'outil (4.4, « Codes d'erreur de l'enregistreur »).

### 0.4 Révisions

La version 0.2 est datée du 2026-10-22 ; elle a ajouté EX-4.43 et suivants
aux identifiants de la version 0.1 (0.1). La version 0.3 est datée du
2026-10-23 : elle applique les lignes de CT-3 §15.2 dont l'emplacement est
CT-2, la politique des codes d'erreur de la révision MCP `2026-07-28` (0.3)
et un contrôle des motifs de rédaction dont le coût est borné.

**Révision 0.3.** Interface du service d'approbation (section 7.5,
nouvelle) : messages `charger`, `evaluer`, `ouvrir`, `decisions`,
`acquitter`, `consommer` et `expiration` de CT-3 §12, réponse d'`evaluer`
avec `ticket_state`, `approval` et `approver_set`, liste `CANDIDATS` de
CT-3 EX-4.11. Propositions de CT-3 §15.2, toutes adoptées et normatives :
refus de sceller une `retenue` d'un ticket déjà décidé (EX-7.17) ;
vérifications de relais RL-1 à RL-4 et MAC de relais (EX-7.21, EX-7.22) ;
envoi des `launched_by` fixes dans `charger` (EX-7.15) ; validation de
`policy.approval.rules` avant le scellement (EX-15.4 pas 3) ; vérification
SG-7 de la séparation des tâches (EX-7.5). Signal d'approbation en résultat
d'outil `isError: true` (EX-4.49) ; codes de l'enregistreur `-31010` à
`-31017` au lieu de `-32010` à `-32017`, `-32015` retiré sans successeur
(4.4, EX-4.24). Contrôle des motifs (EX-10.6 : règles de structure et de
taille) et budget de rédaction appliqué à tout ce que les motifs examinent
(EX-10.23). Conservation de l'`approver_set` des décisions et export dans
`approbations.json` (EX-12.23). Motif d'approbation soumis à la rédaction
(EX-10.24). Mode d'attente `erreur`, requis, dans l'exemple de
configuration, et `rules` désigné par `$ref` vers `politique-approbation-v0`
dans le schéma de configuration (15.3).

La relecture de la révision 0.3 l'a complétée, à la même date, sur les
points suivants. Une continuation MRTR n'hérite d'une décision qu'avec les
mêmes arguments en clair (MAC de relais), un `requestState` à usage unique
et, sous un ticket, RL-1 à RL-4, RL-3 en mode continuation (EX-4.21,
EX-7.21) ; seul le premier `executee` d'un ticket donne `consommer`, dont
certaines réponses sont finales (EX-7.20, CT-3 T22) ; RL-4 a la marge du
délai de l'outil. Une réponse d'`evaluer` a ses six membres dans un ordre
quelconque et, pour `nouveau`, un jeu exploitable ; l'expiration par le
noyau seul prend le dernier jeu exploitable et son seuil (EX-7.16, EX-9.4).
Les lignes `retenue`, `mac` et `decision` des fichiers des approbations sont
écrites avant l'ajout de leur événement au segment ; les continuations y
sont inscrites ; chaque fichier `mac-*` commence par une ligne de contrôle de
la clé, la même pour toutes les instances (EX-12.23, EX-7.22, 13.4). Le
noyau ne scelle pas une seconde `retenue` d'un ticket dont une `retenue`
est durable (4.4 pas 6, EX-7.17) ; en mode dégradé, une remise n'est pas
inscrite (EX-7.19). EX-10.6 ne réécrit que les ouvertures de groupe nommé
reconnues par l'analyse et refuse un quantificateur à zéro non
significatif ; EX-10.23 borne aussi le contrôle des jetons au démarrage,
refuse avant relais un appel d'écriture ou susceptible d'approbation dont la
pièce « arguments » dépasse la borne, remplace un gabarit d'effets sans effet
par l'effet par défaut, et tient pour levé R10 NV-4 ; la borne est un entier
d'au moins 1. Les quotas d'une connexion d'hôte comptent aussi les octets
reçus et le temps de capture (EX-4.47), et la capture s'exécute hors des
fils d'entrée-sortie (EX-3.6). La longueur d'une pièce non rédigeable est
définie (EX-8.7) ; le `path` des règles n'est pas résolu pour une valeur en
ligne (EX-6.6, EX-7.2, EX-8.6, EX-10.18, EX-10.24). L'exemple de 15.3 donne
une identité de séparation au demandeur `poste-cursor` et les quatre quotas
(EX-10.21 change de valeurs) ; la démonstration de la version 0.3 porte une
politique d'approbation conforme, et `journal-demo` reste celle de la
version 0.2 (19.1, 19.2, 19.4, B.6).

- Règles ajoutées : EX-3.6, EX-4.49, EX-4.50, EX-6.7, EX-7.14 à EX-7.22,
  EX-10.24, EX-12.23.
- Règles modifiées : EX-4.8, EX-4.15, EX-4.18, EX-4.21, EX-4.22, EX-4.23,
  EX-4.24, EX-4.28, EX-4.31, EX-4.33, EX-4.46, EX-4.47, EX-4.48, EX-6.4,
  EX-6.6, EX-7.2, EX-7.4, EX-7.5, EX-7.12, EX-8.6, EX-8.7, EX-9.4, EX-10.2,
  EX-10.4, EX-10.6, EX-10.18, EX-10.21, EX-10.23, EX-12.1, EX-12.8, EX-13.6,
  EX-13.10, EX-14.5, EX-14.9, EX-15.1, EX-15.3, EX-15.4, EX-15.5, EX-15.7,
  EX-17.2, EX-19.4 ; pas 1 à 7, 11, 13 et 14 de 4.4 ; paragraphe des fils de
  3.4, rétabli ; tables de 1, 2, 3.2, 3.3, 4.4, 6.2 (résultat de
  `debutAppel` : `ticket_state`, `call` nul hors `autorise`), 9.1, 14.2,
  17.2 et 17.4 ; 13.4 ; 15.3 ; 19.1, 19.2, 19.4 et 19.5 ; section 21 ;
  annexes A, B et C.
- Règles retirées : aucune.
- Vecteurs `spec/vecteurs/ct-2` qui changent : les codes des cas
  `pieces-mcp/appels/{delai,injoignable,taille-depassee}`, les membres
  `approval` et `result_rendered` de tous les `attendu.json` de
  `pieces-mcp`, les cas d'approbation ajoutés à `pieces-mcp`, le signal
  rendu de `journal-demo` (`result_rendered_seq_5`), `redaction/motifs.json`
  (motifs refusés par les règles a) à c) et par le zéro non significatif,
  motifs à « (?P< » avec leur membre `matches`), `INDEX.md` (annexe B). Les
  événements de `journal-demo`, les vecteurs de CT-1 et de CT-6 et les
  formats v0 de CT-1 ne changent pas.

## 1. Objet et périmètre

CT-2 fixe, pour la version 0 de l'enregistreur :

1. l'architecture interne de l'enregistreur, ses composants, ses limites de
   confiance et ce qui tourne dans et hors du processus de l'agent (section 3) ;
2. le **frontal MCP** : position, négociation de version avec l'hôte et avec
   chaque serveur d'outils, agrégation de `tools/list`, relais de `tools/call`
   octet par octet, méthodes relayées hors chaîne, requêtes du serveur vers le
   client, transports stdio et Streamable HTTP, authentification sans relais de
   jeton, exigences réseau (section 4) ;
3. le **frontal modèle** : les modes passerelle, ICAP, miroir et désactivé, la
   passerelle comme mode nominal, les formats d'API de modèle de la version 0
   (API Messages d'Anthropic et ses variantes de corps identique, Chat
   Completions et Responses d'OpenAI) et ceux reportés en version 1, le chemin
   de données en flux et hors flux, le réassemblage des flux SSE en une forme
   consolidée fournisseur par fournisseur, l'extraction de `code.model`, de
   l'intention et du prompt système, la corrélation entre appel d'outil et
   échange de modèle, les erreurs et les délais (section 5) ;
4. le **SDK** : périmètre, interface minimale, limites, exigence de pare-feu,
   langages (section 6) ;
5. la **construction de l'événement CT-1** depuis la capture, champ par champ et
   sorte par sorte, les règles de `ts` et de `seq`, l'horloge (section 7) ;
6. la **sérialisation des pièces** : JCS intégral après rédaction, pièce par
   pièce, pièces non JSON, `media_type`, stockage par `sha256` (section 8) ;
7. le **journal sur lui-même** : ce qui déclenche les quatre événements
   réservés, et le journal d'exploitation hors chaîne (section 9) ;
8. la **rédaction avant hachage**, politique versionnée, détecteurs exacts,
   politique `pii-v1` publiée (section 10, décision ouverte 3) ;
9. les **clés de l'enregistreur**, classes de garde A à D, rotation,
   inscription et révocation (section 11, décision ouverte 2) ;
10. le **stockage en ajout seul**, les segments, le journal d'intention, la
    reprise après arrêt, les supports WORM, la rétention (section 12) ;
11. la **haute disponibilité** à écrivain unique avec bail (section 13) ;
12. le **comportement en panne**, matrice et erreurs rendues (section 14) ;
13. la **configuration**, document unique et schéma (section 15) ;
14. les **objectifs de performance** et la méthode de mesure (section 16) ;
15. la **supervision** (section 17) et la **sécurité de l'enregistreur
    lui-même** (section 18) ;
16. la **démonstration de référence** et les fichiers d'intégration des hôtes
    (section 19) ;
17. la clôture des décisions ouvertes 2 et 3 et le changement apporté à
    l'architecture (section 20), ce que la version ne couvre pas (section 21),
    l'alignement avec le dépôt (section 22) ;
18. la **disposition des vecteurs** `spec/vecteurs/ct-2` (annexe B).

Hors périmètre : le langage des règles d'approbation, leur évaluation, le cycle
de vie des tickets et le mode d'attente par défaut (CT-3, qui clôt la décision
ouverte 4 ; CT-2 fixe le point d'appel, les messages que le noyau échange avec
le service d'approbation, les vérifications qu'il fait avant de sceller une
décision ou de relayer un appel approuvé, et ce que l'enregistreur fait de
chaque réponse, section 7.5) ; le registre, l'inscription et la révocation des
clés (CT-4 ; CT-2 fixe ce que l'enregistreur envoie et attend) ; les ancres RFC
3161 et OpenTimestamps (CT-5) ; la ligne de commande et la sortie du
vérificateur (CT-6) ; la cérémonie des clés, l'analyse de conformité et la
revue de sécurité (CT-7) ; le déploiement, la sauvegarde et l'exploitation du
service (CT-8) ; le plan de tests (CT-9).

Relations avec les autres spécifications :

| Spécification | Ce que CT-2 lui fournit | Ce que CT-2 attend d'elle |
|---|---|---|
| CT-1 | Des événements, manifestes et dossiers conformes ; les vecteurs CT-2 sont vérifiables par les outils de CT-1 | Le format, inchangé |
| CT-3 | Le point d'appel de la politique avant relais (7.2), les messages du noyau au service (7.5), la vérification des remises SG-1 à SG-7 (EX-7.5) et des relais RL-1 à RL-4 (EX-7.21), la classification des outils (4.3, 14), l'objet `approval` recopié dans l'appel relayé et dans le `refusee` d'un ticket décidé (EX-7.12), le signal d'approbation (EX-4.49), les deux comportements d'attente (4.4, EX-4.50), la validation de `policy.approval.rules` (EX-15.4) | Le document `politique-approbation-v0` et son évaluation, la réponse d'`evaluer` (CT-3 §12.3 : `rule`, `decision`, `ticket`, `ticket_state`, `approval`, `approver_set`), les remises signées, la sortie `expire`, la liste des outils susceptibles d'approbation, le mode d'attente par défaut (`erreur`) |
| CT-4 | La clé publique à inscrire, l'événement de rotation (9.1), la racine à enregistrer | L'inscription et la révocation ; jamais un blocage d'appel (14) |
| CT-5 | La racine horaire et le manifeste signé (CT-1 §10) | Les jetons et preuves ; jamais un blocage d'appel (14) |
| CT-6 | Les pièces sous leur `sha256` (8.4) et le journal en segments lisibles sans l'enregistreur (12) | Le vérificateur hors ligne |
| CT-7 | La surface d'attaque (18), les classes de garde (11) | La cérémonie des clés, la revue |
| CT-8 | Les métriques et la santé (17), la disposition du stockage (12) | Déploiement, sauvegarde, restauration |
| CT-9 | Les identifiants EX, les vecteurs (annexe B), la méthode de mesure (16) | Les tests |

## 2. Terminologie

Les termes de CT-1 §2 (journal, événement, pièce, référence, période,
manifeste, racine, dossier, vérificateur, approbateur, JCS) gardent leur sens.
S'y ajoutent, fixés pour toute la spécification :

| Terme | Définition |
|---|---|
| Enregistreur | Le logiciel noortrace déployé chez le client : frontaux, noyau, stockage, signataire, supervision. Il est l'écrivain unique d'un journal. |
| Hôte | L'application qui exécute l'agent et porte le client MCP (Claude Desktop, Claude Code, Cursor, un agent écrit avec le SDK Agents d'OpenAI ou LangGraph, …). L'hôte est hors de la confiance de l'enregistreur. |
| Agent | Le programme, piloté par un modèle, qui agit par appels d'outils et échanges de modèle dans l'hôte. |
| Serveur d'outils | Un vrai serveur MCP du client, en amont de l'enregistreur (ERP, CRM, fichiers, base de données). |
| Frontal MCP | Le serveur MCP mandataire de l'enregistreur : serveur pour l'hôte, client pour chaque serveur d'outils. |
| Frontal modèle | La capture à la frontière du modèle, dans l'un des modes de la section 5.1. |
| Passerelle | Mode nominal du frontal modèle : l'hôte adresse ses requêtes d'API de modèle à l'enregistreur par l'URL de base de son SDK, l'enregistreur les relaie au fournisseur. |
| Mode ICAP | Le mandataire HTTPS existant du client, qui intercepte TLS, soumet requêtes et réponses à l'enregistreur par ICAP (RFC 3507). |
| Mode miroir | Copie passive du trafic déchiffré fournie par un équipement du client ; preuve en lecture seule, ne peut rien bloquer. |
| SDK | Bibliothèque dans le processus de l'agent qui remet à l'enregistreur ce qu'elle voit ; acceptée seulement avec un pare-feu de sortie. |
| Connecteur stdio | Programme mince lancé par l'hôte comme serveur MCP stdio, qui relaie les lignes JSON-RPC vers le démon de l'enregistreur par une prise locale ; sans clé ni stockage. |
| Démon | Le processus de l'enregistreur qui porte le noyau, le stockage, le bail et l'accès au signataire ; distinct du processus de l'hôte et de celui de l'agent. |
| Noyau | Construction, rédaction, sérialisation, scellement (hachage et signature) et chaînage des événements. |
| Signataire | Le composant ou service qui détient la clé Ed25519 et produit les signatures (classes de garde A à D, section 11). |
| Pièce | Octets stockés et hachés que référence un événement (CT-1 §5.4). |
| Pièce de définition d'outil | Pièce de contexte (`kind: "autre"`) qui porte la définition d'un outil telle que le frontal l'a servie à la connexion d'hôte dans sa dernière réponse `tools/list` (EX-4.16, EX-4.45). |
| Liste servie | Pour une connexion d'hôte, la liste agrégée des définitions d'outils que le frontal lui a servie au dernier parcours complet de `tools/list` ; sa pièce, `{"tools":[…]}` en JCS intégral, est la pièce de contexte « liste annoncée » (EX-4.45). |
| Forme consolidée | Pour une réponse de modèle reçue en flux SSE, l'objet unique que l'enregistreur réassemble selon les règles de la section 5.4 ; c'est la pièce « réponse ». |
| Journal d'intention | Fichier d'écriture anticipée local, hors chaîne, où l'enregistreur inscrit un appel d'écriture avant de le relayer (12.5). |
| Événement de reprise | Événement `executee`, `is_error: true`, produit à la reprise pour une intention restée sans événement (12.5). |
| Événement en attente | Événement d'un appel de lecture relayé en mode dégradé « stockage », scellé à la sortie du mode dégradé (14.5). |
| Bail | Droit exclusif, à durée limitée, d'écrire un journal (13). |
| Jeton de clôture | Époque du bail, entier monotone inscrit dans l'en-tête de segment, jamais dans l'événement (12, 13). |
| Segment | Fichier NDJSON d'événements complets en JCS v0, un par ligne, précédé d'un en-tête (12). |
| Mode dégradé | État où le stockage, la clé, le bail ou l'horloge sont indisponibles ou hors seuil ; les appels sont bloqués ou passés selon leur classe (14). |
| Journal d'exploitation | Journal technique de l'enregistreur sur lui-même, NDJSON, hors chaîne (9.2). |
| Alias de serveur | Identifiant court et stable d'un serveur d'outils dans la configuration ; sert de préfixe aux noms d'outils annoncés (4.3). |
| Nom d'origine, nom annoncé | Le nom d'un outil tel que le serveur d'outils l'annonce ; le nom sous lequel l'enregistreur l'annonce à l'hôte. `execution.tool` porte le nom annoncé. |
| Classe d'outil | `lecture` ou `ecriture`, d'après la configuration, à défaut l'annotation `readOnlyHint`, à défaut `ecriture` (4.3, 14). |
| Ère moderne, ère héritée | Révision MCP `2026-07-28` et suivantes (métadonnées par requête) ; révisions `2025-11-25` et antérieures (poignée de main `initialize`), vocabulaire de la spécification MCP (R1 Q2). |
| Connexion d'hôte | Le lien par lequel un hôte parle au frontal MCP, au frontal modèle ou au point d'entrée SDK : un processus connecteur stdio, une identité HTTP authentifiée (jeton OAuth ou jeton statique), ou, en modes ICAP et miroir, une adresse source. Elle est décrite par une entrée de `mcp.hosts`, `model.hosts` ou `sdk.hosts` ; la délégation (CT-1 `delegation`) lui est attachée (7.2). |
| Groupe d'hôte | Étiquette `host_group` qu'une entrée de connexion d'hôte porte dans la configuration ; elle relie, pour la corrélation de 5.6, une connexion MCP et une connexion de passerelle qui servent le même agent. Elle est fixée par le client, jamais déclarée par l'hôte. |
| Route de modèle | Entrée de configuration du frontal modèle : un chemin exact, un format v0, un fournisseur amont, ses identifiants, un libellé de fournisseur pour `code.model`, et la liste exacte des couples (méthode, chemin) relayés sans événement (EX-5.2). |
| Ensemble de politique | Le document JSON unique nommé par `code.policy_version` : règles d'approbation (CT-3), règles de rédaction, carte des serveurs d'outils et réglages de panne (7.2, 9.1, 15). |
| Référence de secret | Désignation d'un secret par son emplacement (variable d'environnement, fichier, coffre), jamais sa valeur, dans la configuration (15). |
| Service d'approbation | Le composant de CT-3 que l'enregistreur appelle avant relais et qui lui rend les décisions. |
| Remise | Une décision d'un ticket que le service remet au noyau (message `decisions`, CT-3 §12.5) ; le noyau la vérifie (SG-1 à SG-7, EX-7.5) avant de la sceller. |
| Signal d'approbation | Le résultat d'outil `isError: true`, de texte fixe, que le frontal rend pour un appel dont le ticket est en attente, refusé ou expiré (EX-4.49) ; ce n'est pas une erreur JSON-RPC. |
| MAC de relais | HMAC-SHA-256, sous une clé propre au noyau, du JCS intégral des arguments en clair d'un appel retenu ; il permet de comparer l'appel relayé à la demande approuvée sans garder le clair (EX-7.22). |
| Fichiers des approbations | Fichiers hors chaîne, en ajout seul, où le noyau garde les jeux d'approbateurs reçus du service et les MAC de relais (EX-12.23). |

## 3. Architecture interne de l'enregistreur

### 3.1 Composants

| Composant | Rôle | Section |
|---|---|---|
| Frontal MCP | Serveur MCP pour l'hôte, client MCP pour chaque serveur d'outils ; agrège `tools/list`, relaie `tools/call`, relaie hors chaîne les autres méthodes. | 4 |
| Frontal modèle | Reçoit (passerelle), lit (ICAP) ou observe (miroir) les requêtes d'API de modèle et leurs réponses ; réassemble les flux. | 5 |
| Point d'entrée SDK | Reçoit du SDK, par une prise locale, les appels d'outils et échanges de modèle que l'agent exécute lui-même. | 6 |
| Moteur de politique (point d'appel de CT-3) | Classe l'outil, soumet la demande au service d'approbation, qui évalue la règle, applique sa réponse (`autorise`, `a_approuver` ou `refuse`, état du ticket), gère l'attente de la décision, vérifie les remises et les relais d'appels approuvés. | 7.2, 7.5, 14, CT-3 |
| Rédacteur | Applique les règles de rédaction de l'ensemble de politique aux pièces, avant hachage. | 10 |
| Noyau | Construit l'événement CT-1, sérialise les pièces (JCS intégral) et l'événement (JCS v0), hache, fait signer, chaîne. | 7, 8 |
| Signataire | Détient la clé Ed25519 ; classes de garde A (matériel), B (service de signature), C (enveloppe), D (fichier, développement). | 11 |
| Stockage | Segments d'événements en ajout seul, pièces sous leur `sha256`, journal d'intention, `fsync`. | 12 |
| Bail | Obtient et renouvelle le droit exclusif d'écrire un journal ; fournit le jeton de clôture. | 13 |
| Clôture de période | Toutes les heures UTC, arbre de Merkle, manifeste, signature (CT-1 §9 et §10) ; remet la racine à l'ancrage (CT-5) et au registre (CT-4). | CT-1, CT-4, CT-5 |
| Exportateur de dossier | Produit le dossier d'un événement (CT-1 §11) à partir des segments, des manifestes et des pièces. | CT-6 |
| Configuration | Charge et valide le document unique, résout les références de secrets, recharge la politique. | 15 |
| Supervision | Santé, métriques, journal d'exploitation, alertes. | 17 |

### 3.2 Flux de données

Un appel d'outil par le frontal MCP, dans l'ordre :

1. L'hôte envoie `tools/call` au frontal MCP (ligne stdio reçue par le
   connecteur et relayée au démon, ou corps HTTP POST).
2. Le frontal MCP résout le nom annoncé en (alias de serveur, nom d'origine)
   et retrouve la définition d'outil servie à cette connexion d'hôte et la
   définition courante (EX-4.45).
3. Le moteur de politique classe l'outil et soumet la demande, arguments
   **en clair**, en mémoire, au service d'approbation, qui évalue la règle ;
   sortie `autorise`, `a_approuver` ou `refuse`, et état du ticket (7.5).
4. Le rédacteur produit les arguments rédigés ; le noyau les sérialise en JCS
   intégral : c'est la pièce « arguments », stockée et hachée.
5. Pour un ticket nouveau (`a_approuver`), le noyau scelle et stocke un
   événement `retenue`, remet le ticket au service, puis applique le mode
   d'attente ; pour un ticket en attente, aucun événement, et l'hôte reçoit
   le signal d'approbation ; pour un refus (sans ticket, ou ticket refusé ou
   expiré), un événement `refusee` est scellé et l'hôte reçoit un résultat
   d'outil `isError: true` ; pour `autorise`, suite (après les vérifications
   de relais si le ticket est approuvé).
6. Pour un outil de classe `ecriture`, le stockage inscrit l'intention et la
   force sur disque (`fsync`) avant tout relais.
7. Le frontal MCP envoie l'appel au serveur d'outils ; il relaie à l'hôte, au
   fil de l'eau, les notifications de progression.
8. Le serveur d'outils répond ; le rédacteur et le noyau produisent la pièce
   « résultat ».
9. Le noyau construit l'événement (section 7), le sérialise en JCS v0, le hache
   avec le préfixe de domaine de CT-1 §6.1, le fait signer par le signataire,
   l'ajoute au segment courant ; le stockage vérifie le bail, puis `fsync` ;
   l'intention est levée.
10. Le frontal MCP rend la réponse à l'hôte.

Un échange de modèle par la passerelle suit le même squelette : réception de la
requête HTTP, pièce « requête » (rédigée, JCS intégral) et pièce « prompt
système », relais au fournisseur avec les identifiants choisis par la
configuration, relais de la réponse à l'hôte sans tampon, réassemblage de la
forme consolidée, pièce « réponse », événement `noortrace.modele.echange`. La
politique n'est pas évaluée sur un échange de modèle (`policy.decision =
"sans_objet"`, CT-1 §5.3) ; l'échange n'est jamais retenu.

Le SDK remet au point d'entrée les mêmes grandeurs (outil, arguments, résultat,
durée, erreur ; requête et réponse de modèle) : les pas 3 à 9 s'appliquent, les
pas 1, 7 et 10 n'existent pas.

### 3.3 Limites de confiance

| Frontière | Ce qui la traverse | Confiance |
|---|---|---|
| Hôte et agent ↔ enregistreur | Messages JSON-RPC MCP, requêtes HTTP d'API de modèle, appels SDK | Aucune. Tout ce qui vient de l'hôte est une donnée d'attaquant potentiel : l'agent peut mentir sur sa délégation, forger des `_meta`, répéter des appels. L'enregistreur n'y puise que ce qui est déclaratif par nature (CT-1 §15). |
| Enregistreur ↔ serveurs d'outils | JSON-RPC MCP, identifiants propres de l'enregistreur | Partielle : le serveur est celui du client, mais ses annotations sont « untrusted unless they come from trusted servers » (page Tools, https://modelcontextprotocol.io/specification/2026-07-28/server/tools, R1 Q3) ; ses descriptions sont le vecteur de l'empoisonnement décrit par Invariant Labs et Trail of Bits (R9 F-160, F-170) ; les résultats peuvent contenir des instructions pour le modèle. |
| Enregistreur ↔ fournisseur de modèle | HTTP, identifiants du client ou de l'enregistreur | Partielle : le contenu produit par le modèle est une donnée, jamais une instruction pour l'enregistreur. |
| Enregistreur ↔ signataire | Messages à signer, signatures | Pleine, authentifiée (section 11) : le signataire ne signe que pour l'enregistreur qui détient le bail. |
| Enregistreur ↔ stockage | Segments, pièces, intentions | Pleine : volume dédié, hors d'atteinte de l'agent (section 12, 18). |
| Enregistreur ↔ CT-3, CT-4, CT-5 | Décisions, inscriptions, racines, jetons | Pleine mais non bloquante pour CT-4 et CT-5 (section 14) ; CT-3 rend une décision ou un délai, jamais un appel relayé sans décision ; ses réponses sont vérifiées (forme, EX-7.16 ; remises, SG-1 à SG-7 ; relais, RL-1 à RL-4), parce que celles qui disent `autorise` ou `refuse` ne sont pas signées (EX-18.8). |

**EX-3.1** L'enregistreur NE DOIT PAS tirer d'un message de l'hôte, du serveur
d'outils ou du modèle une décision de sécurité autre que celles que cette
spécification nomme (classification d'un outil par annotation, section 4.3,
dite non fiable ; délégation déclarée, section 7.2).

**EX-3.2** Le processus de l'agent et le processus de l'hôte NE DOIVENT jamais
détenir la clé de l'enregistreur, un identifiant d'un serveur d'outils, un
identifiant de fournisseur de modèle que l'enregistreur porte pour eux, ni un
accès en écriture au stockage du journal.

### 3.4 Processus et fils

| Processus | Où il tourne | Ce qu'il porte |
|---|---|---|
| Démon de l'enregistreur | Service dédié, utilisateur système propre, hôte ou conteneur distinct de celui de l'agent quand c'est possible | Frontaux (serveur HTTP du frontal MCP, passerelle, serveur ICAP, point d'entrée SDK), moteur de politique, rédacteur, noyau, stockage, bail, clôture, exportateur, supervision |
| Connecteur stdio | Processus enfant de l'hôte, lancé par la configuration MCP de l'hôte | Relais de lignes JSON-RPC entre son `stdin`/`stdout` et la prise locale du démon ; aucun état, aucune clé |
| Signataire | Dans le démon (classes C et D), ou hors du démon : service de signature, module matériel (classes A et B) | La clé privée ou son accès |
| Serveurs d'outils stdio | Processus enfants **du démon**, jamais de l'hôte, chacun sous un utilisateur système distinct de celui du démon (EX-3.5) | Les outils du client |
| Serveur ICAP, adaptateur miroir | Dans le démon (ICAP), processus séparé (capture miroir) | Modes alternatifs du frontal modèle |

**EX-3.3** Le démon est un processus distinct de l'hôte et de l'agent. Un
connecteur stdio NE DOIT porter ni clé, ni stockage, ni politique : il
transmet. Le mode « local » où le connecteur embarque le démon (un seul
processus, pour le développement) est admis uniquement avec une clé de classe
D et refusé par la configuration en production (section 11, 15).

**EX-3.4** Un serveur d'outils en transport stdio DOIT être lancé par le démon,
sous l'utilisateur que fixe EX-3.5, avec le bac à sable ou le conteneur que la
configuration prescrit ; il NE DOIT PAS être lancé par l'hôte. La spécification
MCP demande aux mandataires stdio de journaliser tout usage de ce transport,
d'isoler les processus lancés et d'exiger une autorisation supplémentaire pour
les commandes dangereuses (page « Security Best Practices », section « stdio
Transport Security in Proxy Scenarios », R9 F-153) : la commande exacte de
chaque serveur stdio est inscrite dans la configuration et dans le journal
d'exploitation au démarrage.

**EX-3.5** Chaque serveur d'outils stdio DOIT s'exécuter sous un utilisateur
système **distinct de celui du démon** (`policy.servers.<alias>.transport.user`,
un utilisateur par serveur recommandé), qui n'a aucun droit sur
`storage.root`, sur les fichiers de secrets (15.2), sur le fichier de
configuration ni sur les prises du démon. Motif : sous le même utilisateur,
un serveur d'outils malveillant ou compromis lirait les secrets en `0400` du
démon, écrirait sous `storage.root` (segments, journal d'intention, fichier
d'attente) et lirait `/proc/<pid>/environ` du démon, dont l'accès suit un
contrôle ptrace `PTRACE_MODE_READ_FSCREDS` (`proc_pid_environ(5)`,
https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html, lu le
2026-10-22). Le démon lance l'enfant par un auxiliaire privilégié minimal
(`setuid`/`setgid` vers l'utilisateur configuré, puis exécution de la
commande) ou par l'orchestrateur (un conteneur par serveur, CT-8). Sous
Linux, le démon DOIT appeler `prctl(PR_SET_DUMPABLE, 0)` dès son démarrage
(`PR_SET_DUMPABLE(2const)`,
https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html, lu le
2026-10-22), ce qui lui retire la possibilité d'être tracé par un processus
de même utilisateur et désactive ses vidages mémoire ; les autres systèmes
ne sont pas traités en version 0 (non vérifié). En `environment:
"production"`, la validation (15.4) refuse un serveur stdio sans `user`,
ou dont `user` est celui du démon, et refuse une commande qui n'est pas
épinglée : `transport.integrity` DOIT porter soit le `sha256` de
l'exécutable désigné par `command[0]`, que le démon vérifie avant chaque
lancement, soit, pour un lanceur de paquets (`npx`, `uvx`, `pipx`), le nom et
la version exacte du paquet (`"package": "<nom>@<version>"`), que la commande
DOIT contenir tels quels ; `npx -y <paquet>` sans version télécharge un code
nouveau à chaque lancement et est refusé.

Fils du démon : un fil (ou une tâche d'entrée-sortie asynchrone) par
connexion d'hôte et par connexion de serveur d'outils pour l'entrée-sortie ; un
**unique écrivain** par journal pour le noyau et le stockage, qui sérialise
`seq`, `prev_hash`, l'ajout au segment et le `fsync` (section 12 : validation
groupée possible, un `fsync` pour plusieurs événements, sans jamais répondre à
l'hôte avant que l'événement de son appel soit durable) ; un fil pour le bail
(renouvellement) ; un fil pour la clôture horaire ; un fil pour la supervision ;
un groupe de fils de calcul pour la capture (EX-3.6).
Aucune décision de `seq` n'est prise hors de l'écrivain.

**EX-3.6** La rédaction des pièces, l'exécution des motifs sous la borne de
temps d'EX-10.23 et les autres opérations de capture dont le coût suit la
taille des données reçues (analyse JSON, sérialisation des pièces) DOIVENT
s'exécuter hors des fils d'entrée-sortie, de l'écrivain et du bail : sur un
groupe de fils de calcul de taille bornée (par exemple, avec Node.js, des
`Worker` dont un dépassement de la borne arrête l'opération), de sorte
qu'une requête coûteuse d'un hôte ne retarde ni les autres hôtes, ni
l'écriture des événements, ni le renouvellement du bail. Une exécution
synchrone sous `node:vm` (EX-10.23) occupe en effet le fil qui l'appelle
jusqu'à la borne, et au-delà pour la sérialisation : sur un même fil, la
pièce « arguments » de quatre requêtes de 15 Mio sous `pii-v1`, chacune
au-delà d'une borne de 1 000 ms et réduite à la pièce non rédigeable de
96 octets, a pris 5 039 ms, pendant lesquelles un minuteur de 50 ms n'a pas
pu s'exécuter (mesure sous Node.js v22.22.0, le 2026-10-23, avec
`scripts/lib/capture.mjs`). Le temps que consomme chaque hôte est en outre
borné par son quota (EX-4.47).

### 3.5 Dans et hors du processus de l'agent

| | Dans le processus de l'agent | Hors du processus de l'agent |
|---|---|---|
| Frontal MCP | — | Démon (le connecteur stdio, enfant de l'hôte, n'est qu'un tuyau) |
| Frontal modèle, passerelle et ICAP | — | Démon |
| Frontal modèle, miroir | — | Équipement du client et adaptateur |
| SDK | La bibliothèque : capture des appels locaux, envoi au démon | Démon : tout le reste |
| Clé, politique, stockage | jamais | Démon, signataire |

C'est ce qui donne sa valeur au journal : l'étude arXiv 2609.30266 (septembre
2026) montre que, dans tous les harnais testés sauf un, l'agent peut effacer ses
propres traces (architecture, « Capture ») ; une capture faite dans le processus
de l'agent n'a pas de valeur probatoire, et le SDK n'en a que par le pare-feu
qui l'accompagne (section 6).

## 4. Frontal MCP

### 4.1 Position et mise en application par le réseau

Le frontal MCP est un serveur MCP pour l'hôte et un client MCP pour chaque
serveur d'outils. L'hôte est configuré pour ne parler qu'à lui (section 19
donne les fichiers de configuration par hôte) ; lui seul se connecte aux
serveurs d'outils du client, dont il agrège les outils et relaie les appels.

**EX-4.1** Un déploiement conforme DOIT rendre chaque serveur d'outils
injoignable depuis le processus de l'hôte et de l'agent autrement que par
l'enregistreur : serveur stdio lancé par le démon (EX-3.4) ; serveur HTTP
filtré par le pare-feu du client de sorte que seul le démon l'atteigne
(section 4.9). Sans cette règle, le journal prouve ce qui est passé par
l'enregistreur, pas que rien ne l'a contourné (CT-1 §15).

**EX-4.2** Le frontal MCP NE DOIT annoncer aucun outil propre à l'enregistreur
en version 0 : tous les outils annoncés viennent d'un serveur d'outils
configuré. L'espace de noms `noortrace.` reste réservé aux quatre événements de
CT-1 §5.1.

### 4.2 Cycle de vie et négociation de version

L'enregistreur est **dual-era** (R1 Q2) : il sert les hôtes de l'ère moderne
(`2026-07-28`) et de l'ère héritée (`2025-11-25`, `2025-06-18`,
`2025-03-26`), et il parle à chaque serveur d'outils dans l'ère que ce serveur
sait parler. Les deux négociations sont indépendantes.

**EX-4.3** Côté hôte, le frontal MCP DOIT accepter les révisions
`2026-07-28`, `2025-11-25`, `2025-06-18` et `2025-03-26`. Il DOIT implémenter
`server/discover` (« Servers MUST implement it », page `server/discover`
2026-07-28, R1 Q2) et répondre `supportedVersions:
["2026-07-28","2025-11-25","2025-06-18","2025-03-26"]`. Il NE DOIT PAS
accepter le transport HTTP+SSE de `2024-11-05` (déprécié depuis `2025-03-26`,
reclassé « Deprecated » en `2026-07-28`, R1 Q1) : une connexion de cette forme
est refusée et notée dans le journal d'exploitation. Un **lot** JSON-RPC (un
tableau de messages), admis par la révision `2025-03-26` et retiré en
`2025-06-18` (« Added support for JSON-RPC batching », puis « Remove support
for JSON-RPC batching », changelogs
https://modelcontextprotocol.io/specification/2025-03-26/changelog et
https://modelcontextprotocol.io/specification/2025-06-18/changelog, R1 Q1),
n'est pas pris en charge, de quelque côté qu'il vienne : le frontal répond à
un lot reçu d'un hôte par une seule erreur `-32600` (`id: null`,
`data: {"reason": "lot_non_pris_en_charge"}`) sans relayer aucun élément ni
écrire d'événement, et ignore, en le consignant, un lot reçu d'un serveur
d'outils (l'appel en vol finit par délai, EX-4.22).

**EX-4.4** Côté hôte, ère moderne : chaque requête porte
`_meta["io.modelcontextprotocol/protocolVersion"]` et
`_meta["io.modelcontextprotocol/clientCapabilities"]` (requis), et DEVRAIT
porter `_meta["io.modelcontextprotocol/clientInfo"]` ; une requête sans champ
requis est rejetée par l'erreur JSON-RPC `-32602` (HTTP `400`), une version non
supportée par `-32022` (`UnsupportedProtocolVersion`) avec
`data.supported`, en reprenant mot pour mot le format de la page « Versioning
and Compatibility » 2026-07-28 (R1 Q2). Chaque résultat rendu porte
`_meta["io.modelcontextprotocol/serverInfo"] = {"name":
"noortrace-enregistreur", "version": <code.recorder>}`.

**EX-4.5** Côté hôte, ère héritée : la première requête est `initialize` ; le
frontal répond la même version si elle est dans sa liste, sinon la plus
récente des révisions **héritées** de sa liste, `2025-11-25` (la page
Lifecycle 2025-11-25 demande « the latest version supported by the server »,
https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle,
R1 Q2 ; `2026-07-28` n'a pas d'`initialize` et ne peut pas être rendue dans un
`InitializeResult`), attend
`notifications/initialized`, répond à `ping` par `{}` et, en HTTP, applique les
sessions de la section 4.7. Aucune requête autre que `ping` n'est servie avant
`initialized`.

**EX-4.6** Côté serveur d'outils, le frontal DOIT déterminer l'ère de chaque
serveur à la première connexion et mémoriser le verdict pour la durée du
processus (stdio) ou de l'origine (HTTP), comme la spécification le demande
aux clients (page Versioning 2026-07-28, R1 Q2) :

1. stdio : envoyer `server/discover` ; une réponse `result` avec
   `supportedVersions` établit l'ère moderne ; toute erreur **non reconnue
   comme une erreur moderne** (`-32020`, `-32021`, `-32022`) ou l'absence de
   réponse dans le délai `discover_timeout_ms` fait basculer en ère héritée
   (`initialize`). « The fallback MUST NOT be keyed to one specific error code »
   (page stdio 2026-07-28, R1 Q2).
2. Streamable HTTP : envoyer la première requête en forme moderne ; sur `400
   Bad Request`, inspecter le corps : s'il n'est pas une erreur JSON-RPC
   moderne reconnue, basculer en `initialize` ; un `401` ou `403` n'est jamais
   un indice d'ère (c'est une question d'autorisation, section 4.8).
3. La configuration PEUT épingler l'ère d'un serveur (`protocol: "2026-07-28"`
   ou `protocol: "legacy"`) ; l'épinglage supprime la sonde et toute bascule.

**EX-4.7** Le frontal NE DOIT PAS relayer d'un côté à l'autre la version de
protocole, les `clientInfo`, les `serverInfo` ni les capacités : il réécrit
`_meta["io.modelcontextprotocol/protocolVersion"]` avec la version négociée
avec **ce** serveur, `clientInfo` avec sa propre identité, et déclare comme
`clientCapabilities` vers le serveur l'intersection entre ce que l'hôte a
déclaré et ce que la configuration autorise à relayer (section 4.6). Vers un
serveur d'ère héritée, ces capacités sont déclarées une fois dans `initialize`
avec celles de la première requête d'hôte qui provoque la connexion ; un hôte
qui change ensuite de capacités sur une connexion héritée n'est pas suivi
(limite de la version 0, notée dans le journal d'exploitation).

**EX-4.8** Capacités annoncées par le frontal à l'hôte : `tools: { listChanged:
true }` toujours ; `resources`, `prompts`, `completions` seulement si la
configuration autorise leur relais (section 4.5) et si au moins un serveur les
annonce ; `extensions` : aucune en version 0 (l'extension `tasks`
`io.modelcontextprotocol/tasks` n'est pas relayée : un serveur qui rendrait un
`resultType: "task"` provoque l'erreur `-31016`, section 4.4, parce que le
frontal n'a pas déclaré l'extension à l'hôte).

Arrêt : à la fermeture de son entrée standard, un connecteur stdio ferme la
prise vers le démon et se termine ; le démon traite les requêtes en vol
jusqu'au délai `drain_timeout_ms`, scelle ou abandonne (section 14 : une
requête d'écriture en vol dont la réponse n'arrive pas donne l'événement de
reprise de la section 12), puis ferme ses serveurs d'outils stdio dans l'ordre
de la spécification : fermeture de leur entrée standard, attente, `SIGTERM`
après `child_exit_timeout_ms`, `SIGKILL` après le même délai à nouveau (page
stdio 2026-07-28,
https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio,
qui demande de terminer le processus « using the mechanism appropriate for
the operating system », et page Lifecycle 2025-11-25,
https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle, qui
nomme `SIGTERM` puis `SIGKILL` ; R1 Q2).

### 4.3 Agrégation de `tools/list`

**Nommage.** La spécification MCP borne les noms d'outils (SHOULD) à 1–128
caractères parmi `A-Z a-z 0-9 _ - .`, sensibles à la casse, uniques par
serveur, et demande (SHOULD) aux mandataires qui agrègent plusieurs serveurs
une stratégie de désambiguïsation, « such as prefixing tool names with a
server identifier », sans se fier à `serverInfo.name` (page Tools
2026-07-28, section « Tool Names »,
https://modelcontextprotocol.io/specification/2026-07-28/server/tools, R1 Q3
et R9 F-01, F-02) : le préfixe est un exemple de stratégie, celle que CT-2
retient. CT-1
impose à `execution.tool` le motif `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`.
L'API Messages d'Anthropic n'admet dans un nom d'outil que
`^[a-zA-Z0-9_-]{1,128}$` (référence Messages, objet `Tool`, R9 F-04) : le point
y est refusé, et Claude Code remplace par `_` tout caractère hors `A-Z a-z 0-9
_ -` dans ses noms complets `mcp__<server>__<tool>` (R9 F-05, R7 F-28). Le
séparateur retenu est donc le double trait bas, le seul qui soit dans
l'alphabet de MCP, dans le motif de CT-1 et dans l'alphabet d'Anthropic, et qui
reste non ambigu si l'alias ne contient pas de trait bas.

**EX-4.9** Un alias de serveur DOIT respecter `^[a-z0-9][a-z0-9-]{0,31}$` ; les
alias sont uniques dans la configuration ; l'alias `noortrace` est réservé et
refusé.

**EX-4.10** Le nom annoncé d'un outil est `<alias>__<nom d'origine>` (deux
traits bas). Si un seul serveur d'outils est configuré, la configuration PEUT
désactiver le préfixe (`tools.prefix: false`) : le nom annoncé est alors le nom
d'origine. Le nom annoncé DOIT respecter le motif de CT-1 et être d'au plus
128 caractères ; un alias n'ayant pas de trait bas, le découpage au premier
`__` rend toujours l'alias et le nom d'origine.

**EX-4.11** À la configuration et à chaque rafraîchissement de la liste, le
frontal DOIT **rejeter** (ne pas annoncer, consigner dans le journal
d'exploitation avec `tool_rejected` et la raison) les outils suivants ; la
raison est l'une des valeurs fixes entre parenthèses, qui sont aussi celles
des vecteurs de l'annexe B :

1. un outil dont le nom d'origine commence par `noortrace.` (`nom_reserve`) ;
2. un outil dont le nom annoncé ne respecte pas le motif de CT-1 ou dépasse
   128 caractères (`nom_invalide`) ;
3. **tous** les outils dont le nom annoncé est identique, ou devient
   identique après application du gabarit `tool_name_template` et de la
   normalisation `tool_name_sanitize` de l'une des connexions d'hôte
   configurées (EX-5.22 ; Claude Code remplace `.` par `_`), à celui d'un
   autre outil annoncé (`collision`) : aucun des homonymes n'est annoncé,
   parce qu'en retenir un dépendrait de l'ordre d'arrivée des listes. Une
   collision est possible sans préfixe, si deux outils d'un même serveur
   portent le même nom (ce que la spécification interdit en SHOULD), ou après
   normalisation (`demo__a.b` et `demo__a_b`) ;
4. en transport HTTP vers l'hôte, un outil dont une propriété `x-mcp-header`
   viole les contraintes de la page Streamable HTTP (« Rejection means the
   client MUST exclude the invalid tool from the result of `tools/list` », R1
   Q3) (`x_mcp_header`).

Au rafraîchissement, la règle 3 s'applique à la nouvelle liste entière : un
outil en service disparaît de la liste si un serveur ajoute un homonyme, et
réapparaît quand l'homonyme disparaît ; chaque transition est consignée et
notifiée à l'hôte par `list_changed` (EX-4.15). Un rejet n'arrête pas
l'enregistreur ; une collision au démarrage DOIT être signalée dans la sortie
de la commande de validation de la configuration (section 15), et une
configuration sans préfixe où deux serveurs sont déclarés est refusée
(`configuration_refusee`, EX-4.10).

**EX-4.12** Les noms d'origine qui contiennent un point sont annoncés tels
quels (le point est admis par MCP et par CT-1) ; la documentation
d'intégration (section 19) avertit que l'API Messages d'Anthropic les refuse
et que Claude Code les normalise. L'enregistreur ne réécrit jamais un nom
d'origine autrement que par le préfixe.

**Pagination.** **EX-4.13** Le frontal DOIT parcourir toutes les pages de
chaque serveur (`cursor` opaque, « clients MUST NOT assume a fixed page size »,
page Pagination, R1 Q4), dans les bornes `limits.tools_list_max_pages`
(défaut 100) et `limits.tools_list_max_items` (défaut 10 000) par serveur ;
un serveur qui les dépasse est traité, pour ce rafraîchissement, comme
injoignable (EX-4.18, raison `liste_trop_longue`), pour construire sa liste
agrégée, puis servir sa propre
pagination : page de `tools.page_size` outils (défaut 100), curseur opaque
propre au frontal, ordre déterministe par alias puis par nom d'origine
(comparaison des unités UTF-16, celle de CT-1 §4), ce que la spécification
2026-07-28 recommande (« Servers SHOULD return tools in a deterministic
order », R1 Q3). Un curseur invalide rend `-32602`.

**Résultat agrégé (ère moderne).** **EX-4.14** Le résultat de `tools/list`
porte `resultType: "complete"`, `ttlMs` = le plus petit `ttlMs` reçu des
serveurs modernes de la page, ou `tools.default_ttl_ms` (défaut 300000) si un
serveur hérité y figure, et `cacheScope: "private"` si un serveur a répondu
`"private"` ou si l'hôte est authentifié par un jeton porteur d'une identité
(section 4.8), `"public"` sinon (page Caching 2026-07-28, R1 Q4).

**`list_changed`.** **EX-4.15** Vers chaque serveur moderne, le frontal ouvre
`subscriptions/listen` avec `toolsListChanged: true` dès la connexion ; vers un
serveur hérité, il reçoit `notifications/tools/list_changed` sur le flux de la
connexion. À réception, il relit la liste du serveur, applique EX-4.11, et,
si la liste agrégée a changé, renvoie au service d'approbation le message
`charger` (EX-7.15) ; puis il
notifie l'hôte : `notifications/tools/list_changed` sur le flux
`subscriptions/listen` ouvert par un hôte moderne qui a demandé
`toolsListChanged`, sur le flux GET ou `stdout` d'un hôte hérité. Sur stdio,
si la connexion au serveur est rétablie après une coupure, le frontal renvoie
`subscriptions/listen` (page Subscriptions, R1 Q9). Le frontal relit la liste
d'un serveur au plus une fois par `tools.list_changed_min_interval_ms`
(défaut 1 000) : les notifications plus rapprochées sont fusionnées en une
relecture à la fin de l'intervalle, et leur nombre est consigné ; un serveur
ne peut donc pas faire tourner le journal d'exploitation ni occuper le
frontal par des `list_changed` répétés.

**Empreintes des définitions.** **EX-4.16** Pour chaque outil annoncé, le
frontal DOIT calculer et conserver `sha256(JCS_integral(definition))`, où
`definition` est l'objet `Tool` tel qu'annoncé à l'hôte (nom annoncé,
`title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons`,
`_meta` : exactement les membres présents dans l'annonce, rien d'autre), et
consigner dans le journal d'exploitation toute apparition, disparition ou
changement d'empreinte (`tool_definition_changed`, avec l'ancienne et la
nouvelle empreinte). Chaque appel de l'outil référence comme pièces de
contexte la définition **servie à la connexion d'hôte** et, si elle diffère,
la définition courante, ainsi que la liste servie (EX-4.45). C'est la réponse
de l'enregistreur à l'empoisonnement de description (Invariant Labs,
2025-04-01 ; Trail of Bits, 2025-04-21, qui parle de « line jumping » ;
OWASP MCP Top 10, MCP03) et au « rug pull » (Invariant Labs,
https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks),
contre lesquels ces trois sources recommandent une empreinte, une revue ou
un épinglage des définitions (R9 F-160, F-170, F-181, C-09) : l'enregistreur
ne bloque pas un changement de description en version 0, il le rend
prouvable.

**Annotations.** **EX-4.17** Les `annotations` d'un outil (`readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`, `title`) sont relayées
telles quelles et considérées comme **non fiables** (« clients MUST consider
tool annotations to be untrusted unless they come from trusted servers », page
Tools, R1 Q3). La classe d'un outil vient d'abord de la configuration du
client, à défaut de `readOnlyHint: true` → `lecture`, à défaut `ecriture`
(section 14). Un `readOnlyHint` sert donc à passer un appel en mode dégradé :
la configuration DEVRAIT nommer explicitement la classe de tout outil qui écrit.

**Serveur indisponible à `tools/list`.** **EX-4.18** Un serveur injoignable au
moment d'un `tools/list` n'est pas une erreur pour l'hôte : ses outils sont
omis de la liste (comportement « fail-open » de liste ; les portails MCP de
Cloudflare omettent de même de leurs listes de ressources les serveurs qui ne
répondent pas, « Servers that cannot connect or respond are omitted from the
result »,
https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/,
R9 F-82), l'omission est consignée, la santé passe à `degraded` (section
17). Ses outils reviennent au rafraîchissement suivant, avec `list_changed`.
Le relais d'un `tools/call` vers un serveur injoignable est, lui, une erreur :
le pas 2 de 4.4 résout le nom sur la **dernière liste reçue avec succès de
chaque serveur**, de sorte qu'un outil omis parce que son serveur est
injoignable rend `-31014` (section 4.4), et non `-32602` « Unknown tool ».

### 4.4 Relais de `tools/call`

Séquence pour un appel reçu d'un hôte moderne, relayé à un serveur moderne
(les différences d'ère sont en fin de section). Les instants `t_recu`,
`t_envoi`, `t_reponse` sont lus sur l'horloge monotone de l'enregistreur ;
`ts` de l'événement est lu sur l'horloge murale selon la section 7.4.

1. **Lecture.** Le frontal lit une ligne (stdio) ou le corps POST (HTTP),
   octets UTF-8 ; `t_recu`. Une ligne (stdio, connecteur, démon) qui
   contient un CR (U+000D) est rejetée par `-32700` avec `data: {"reason":
   "cr_dans_la_ligne"}` et `id: null` (EX-4.43) ; un corps POST n'est pas une
   ligne, et un CR y est un blanc. Il analyse le JSON strictement (texte
   conforme à la RFC 8259 ; clés en double, substituts isolés et marque
   d'ordre d'octets refusés ; profondeur d'imbrication au plus
   `limits.json_max_depth`, défaut 128, et au plus `limits.json_max_members`
   membres ou éléments par objet ou tableau, défaut 100 000) tout en relevant
   la **position en octets** du membre `params.arguments` dans le texte reçu.
   Une ligne qui n'est pas du JSON strict, ou qui dépasse ces bornes, rend
   `-32700` ; un lot, `-32600` (EX-4.3) ; une requête mal formée, `-32600` ;
   `_meta` incomplet, `-32602` (EX-4.4) ; des arguments que la pièce ne peut
   pas représenter exactement, `-32602` (EX-4.44). Aucune de ces erreurs ne
   produit de pièce, d'intention ni d'événement. Taille : au-delà de
   `limits.request_max_bytes` (défaut 16 777 216), la lecture s'arrête et le
   frontal rend `-31013` sans relayer ; aucune pièce n'est écrite, le
   journal d'exploitation note la taille reçue. Les quotas de la connexion
   d'hôte (EX-4.47 : requêtes en cours, octets reçus, octets de pièces, temps
   de capture) sont vérifiés ici ; les octets reçus sont comptés même pour
   une requête refusée.
2. **Résolution.** `params.name` est découpé au premier `__` (ou pris tel quel
   sans préfixe) et cherché dans la dernière liste reçue avec succès de
   chaque serveur (EX-4.18) ; un nom qui n'y est pas rend
   `{"code": -32602, "message": "Unknown tool: <nom>"}`, la forme exacte de
   la page Tools (R1 Q3) ; un nom d'un serveur injoignable rend `-31014`. La
   définition servie à cette connexion d'hôte et la définition courante
   donnent les pièces de contexte (EX-4.45) ; la définition courante donne
   la classe (EX-14.1).
3. **Politique.** Le moteur de politique soumet au service d'approbation
   (message `evaluer`, EX-7.4) le nom annoncé, le nom d'origine, l'alias, les
   arguments **en clair** (valeur JSON analysée), la classe, la délégation de
   la connexion d'hôte et l'intention corrélée (section 5.6), et reçoit la
   réponse de CT-3 §12.3 : `rule`, `decision`, `ticket`, `ticket_state`,
   `approval`, `approver_set`. Une réponse hors des combinaisons d'EX-7.16,
   ou une erreur du service, est une indisponibilité du service (14.2). Le
   pas 5 traite un refus, le pas 6 un ticket nouveau ou en attente ; une
   réponse `autorise` sans ticket poursuit au pas 4. Une réponse `autorise`
   d'un ticket `approuve` (ré-émission reconnue d'un appel approuvé, CT-3
   EX-7.16) poursuit au pas 4, avec les vérifications de relais RL-1 à RL-4
   au pas 7 (EX-7.21) ; l'appel relayé reprend de l'événement `retenue` de
   ce ticket, clé pour clé, `policy.decision` (`a_approuver`), `policy.rule`,
   `policy.ticket`, `intent`, `code.model` et `code.prompt_version`, quel que
   soit le mode d'attente (EX-7.12) ; la corrélation de 5.6 n'est pas
   refaite. Pour un ticket `nouveau` ou `approuve`, pour une ré-émission
   `en_attente` que le mode `retenir` retient (EX-4.50), et pour tout appel
   relayé (son résultat peut être `input_required` et ouvrir une
   continuation MRTR, EX-4.21), le noyau calcule ici, sur les arguments en
   clair, le MAC de relais (EX-7.22).
4. **Pièce « arguments ».** Le rédacteur applique les règles de portée
   `arguments` de l'ensemble de politique à la valeur analysée ; le noyau
   sérialise le résultat en JCS intégral (section 8) ; la pièce est écrite
   sous son `sha256` et forcée sur disque. La valeur en clair ne quitte pas la
   mémoire. Si la rédaction dépasse la borne de temps (EX-10.23) pour un
   outil de classe `ecriture` ou susceptible d'approbation, et que la réponse
   du pas 3 mène à un relais ou à un événement `retenue`, le frontal rend
   `-31010`, raison `redaction`, sans intention ni événement : un appel
   d'écriture ne part jamais sans ses arguments dans la preuve, et les
   approbateurs ne voient jamais une demande vide (EX-10.23).
5. **Refus.** Pour une réponse `refuse` sans ticket, le noyau scelle un
   événement `status: "refusee"` (`policy.decision: "refuse"`, `rule` de la
   réponse, `ticket: null`, `approval: null`, section 7.2), le stockage
   l'ajoute et `fsync` ; le frontal rend à l'hôte le résultat `isError: true`
   au texte fixe `noortrace: appel refuse par la politique` (EX-4.49, CT-3
   EX-11.8) ; fin. Pour une réponse `refuse` d'un ticket décidé
   (`ticket_state` `refuse` ou `expire` : ré-émission reconnue pendant le
   délai de reconnaissance, CT-3 EX-7.18), l'événement `refusee` reprend la
   `policy` de l'événement `retenue` du ticket et porte l'`approval` de la
   décision que le noyau a scellée pour lui (EX-7.12, EX-7.16) ; le frontal
   rend le signal d'approbation dont `state` est `ticket_state` (EX-4.49) ;
   fin. Chaque tentative refusée est un événement (EX-14.3).
6. **Ticket nouveau ou en attente.** Pour `ticket_state: "nouveau"`, le noyau
   vérifie qu'aucune décision n'est scellée pour ce ticket (EX-7.17) et
   qu'aucun événement `retenue` sans décision de ce ticket n'est déjà durable
   (sinon, le service garde le ticket en `reserve` faute d'avoir reçu
   `ouvrir` : le noyau ne scelle rien, renvoie `ouvrir` pour la `retenue`
   durable, consigne `approval_pending` et répond comme pour `en_attente`
   ci-dessous) ; puis il scelle un événement `status: "retenue"` (son `hash`
   devient le `request_hash` du ticket) : l'écrivain, après l'avoir signé et
   avant de l'ajouter au segment, inscrit dans les fichiers des approbations
   l'`approver_set` de la réponse et le MAC de relais, `fdatasync`
   (EX-12.23), puis l'ajoute, `fsync` ; le frontal répond à l'hôte selon le
   mode d'attente de la configuration et le noyau remet le ticket au service
   (`ouvrir`, EX-7.18), sans attendre la réponse d'`ouvrir` pour répondre à
   l'hôte. `approval.mode: "erreur"` (la valeur de la configuration de
   référence, CT-3 EX-11.1) rend aussitôt le signal d'approbation `en_attente`
   (EX-4.49), et l'agent ré-émet l'appel, qui repasse par le pas 3 ;
   `approval.mode: "retenir"` garde la requête de l'hôte ouverte jusqu'à la
   décision ou jusqu'à `approval.hold_timeout_ms` (EX-4.50). Pour
   `ticket_state: "en_attente"`, aucun événement n'est produit (CT-3
   EX-7.19) : le frontal rend aussitôt le signal `en_attente` et consigne
   `approval_pending`, sauf en mode `retenir` quand aucune requête n'est
   retenue pour ce ticket, où cette requête est retenue (EX-4.50). Dans les
   deux modes, l'appel relayé après une décision `approuve` porte la
   `policy` de l'événement `retenue` (`decision: "a_approuver"`, `rule`,
   `ticket`), son `intent` et son `code` (pas 3, EX-7.12), comme l'exemple
   de CT-1 §5.5. La décision elle-même devient un événement
   `noortrace.approbation.decision` (section 9.1, EX-7.19) avant tout
   relais.
7. **Préconditions de relais.** Pour un appel qui porte un ticket approuvé
   (pas 3, ou continuation MRTR qui en hérite, EX-4.21), les vérifications
   de relais RL-1 à RL-4 (EX-7.21) sont faites d'abord ; un échec rend
   `-31010`, raison `approbation`, sans intention ni événement. Pour un outil
   de classe `ecriture` ou soumis à approbation : le bail est détenu, le
   signataire répond, le stockage accepte une écriture ; sinon, comportement
   de la section 14 (`-31010`).
   Pour un outil de classe `lecture`, une indisponibilité du **stockage**
   rend le relais `passant` : l'appel est relayé, l'événement est mis en
   attente (section 14) ; une clé ou un bail indisponible bloque tout
   (EX-14.4). Pour toute classe, la connexion au serveur d'outils est
   établie (processus stdio vivant, connexion HTTP ouverte) **avant** le pas
   8 : une connexion impossible rend `-31014` sans intention ni événement,
   puisque rien n'est parti.
8. **Intention.** Pour un outil de classe `ecriture` ou soumis à approbation,
   le stockage ajoute au journal d'intention les **deux lignes** de la
   section 12.5 : la ligne intention (`intent_id`, `upstream_id`, `host`,
   `journal_id`, `org_id`, `tool`, `arguments`, `ticket`, `written_at`), puis
   la ligne de contexte d'intention (l'événement partiel déjà construit :
   `delegation`, `code`, `intent`, `policy`, `approval`, référence des
   arguments, `effects` déclarés, `context`), et `fsync` **avant** le pas 9.
9. **Envoi.** Le frontal construit le message amont : `jsonrpc: "2.0"` ; `id`
   = identifiant propre au frontal, unique par connexion amont (`e-` suivi
   d'un compteur décimal sur douze chiffres) ; `method: "tools/call"` ;
   `params.name` = nom d'origine ; `params.arguments` = **les octets reçus au
   pas 1, recopiés sans réanalyse, blancs non significatifs retirés**
   (EX-4.43) ; `params._meta` = les clés
   `io.modelcontextprotocol/*` réécrites (EX-4.7), `progressToken` remplacé
   par un jeton propre (`p-<compteur>`) mémorisé, `traceparent`,
   `tracestate`, `baggage` relayés tels quels (page Overview, trace context,
   R1 Q9), toute autre clé `_meta` relayée telle quelle ; `inputResponses` et
   `requestState` d'une ré-émission MRTR relayés octet pour octet (« the
   client MUST echo back the exact value », page MRTR, R1 Q5), blancs non
   significatifs retirés. En HTTP, les en-têtes `MCP-Protocol-Version`,
   `Mcp-Method: tools/call`, `Mcp-Name: <nom d'origine>` et les
   `Mcp-Param-*` sont construits d'après le corps relayé et la définition
   courante, jamais recopiés de l'hôte (EX-4.35). `t_envoi`.
10. **Notifications en vol.** Chaque `notifications/progress` du serveur dont
    le `progressToken` est connu est relayée à l'hôte avec le jeton d'origine,
    sans attendre ; `notifications/message` est relayée telle quelle ; ni
    l'une ni l'autre n'entrent dans la chaîne ; leur nombre est noté.
11. **Réponse.** Le frontal lit la réponse (objet JSON, ou dernier événement
    SSE portant la réponse) ; `t_reponse` ; `duration_ms = t_reponse −
    t_envoi`, arrondi à l'entier inférieur. Au-delà de
    `limits.response_max_bytes` (défaut 16 777 216), la lecture s'arrête, la
    connexion amont est fermée (ce qui vaut annulation en HTTP), et l'appel
    est traité comme une erreur `-31013`. Une ligne amont qui contient un CR,
    n'est pas du JSON strict ou est un lot est ignorée et consignée
    (`invalid_line`) : l'appel en vol finit par délai. **Issues sans
    réponse** (EX-4.48) : `t_reponse` vaut `t_envoi + timeout_ms` pour un
    délai (EX-4.22), l'instant d'envoi de l'annulation amont pour une
    annulation par l'hôte (EX-4.23), l'instant où la perte est constatée
    (fin de fichier sur la sortie standard, fin du processus, erreur ou
    fermeture de la connexion) pour un serveur qui meurt ou une connexion
    coupée (`-31014`), et l'instant où la borne est atteinte pour une taille
    dépassée.
12. **Pièce « résultat ».** Si la réponse porte `result` et que `result` est
    un objet JSON : le rédacteur
    applique les règles de portée `resultat` à la valeur `result` entière
    (`resultType`, `content`, `structuredContent`, `isError`, `_meta`, telle
    que reçue du serveur, avant toute réécriture par le frontal), le noyau la
    sérialise en JCS intégral ; `is_error = (result.isError === true)`. Si la
    réponse porte `error` : la pièce est l'objet
    `{"noortrace_jsonrpc_error": <objet error reçu, membres présents
    seulement>}` en JCS intégral, `is_error = true`. La distinction entre
    erreur de protocole (`error`) et erreur d'exécution (`isError`) est celle
    de la page Tools (R1 Q3) ; la chaîne garde les deux, sous deux formes.
    Si `result` n'est pas un objet (chaîne, nombre, tableau, `null`), la
    réponse est une erreur de protocole du serveur : la pièce est
    `{"noortrace_jsonrpc_error": {"code": -32603, "message": "noortrace:
    resultat amont invalide", "data": {"result_type": "<string|number|boolean|array|null>"}}}`,
    `is_error = true`, et l'hôte reçoit cette même erreur `-32603` (pas 14) ;
    le frontal n'émet jamais un texte qui n'est pas du JSON.
13. **Événement.** Le noyau construit l'événement `status: "executee"`
    (section 7.2), le scelle, l'écrivain l'ajoute au segment après avoir
    vérifié le bail, `fsync`, puis revérifie le bail auprès du magasin
    (EX-13.10) ; l'intention du pas 8 est levée. En validation groupée,
    plusieurs événements partagent un `fsync`, mais le pas 14 n'a lieu
    qu'après celui qui couvre cet événement. Une panne entre le pas 9 et la
    fin de ce pas (stockage, signataire, signature invalide, bail perdu,
    événement qui échoue E-1 à E-7) suit EX-4.46 : l'hôte reçoit `-31017`,
    jamais `-31010`. Quand l'événement est le premier `executee` qui porte
    l'approbation de son ticket, le noyau envoie ensuite `consommer` au
    service (EX-7.20), sans retarder le pas 14 ; une continuation MRTR qui en
    hérite (EX-4.21) n'en envoie pas. Quand le résultat est `input_required`,
    le noyau garde, avant le pas 14, l'enregistrement de continuation
    d'EX-4.21.
14. **Réponse à l'hôte.** Le frontal rend `{"jsonrpc":"2.0","id": <id reçu au
    pas 1>, "result": …}` où l'`id` est **les octets de l'`id` reçu au pas 1**,
    recopiés depuis le texte de l'hôte (un entier au-delà de 2^53 n'est pas
    altéré), et `result` est **les octets reçus au pas 11** recopiés, blancs
    non significatifs retirés (EX-4.43), avec deux réécritures :
    `_meta["io.modelcontextprotocol/serverInfo"]` remplacé par l'identité de
    l'enregistreur (EX-4.4), et `resultType: "complete"` ajouté s'il manque
    et que l'hôte est moderne (« All results now carry a required
    `resultType` field », changelog 2026-07-28, R1 Q1). Une erreur JSON-RPC
    du serveur est rendue avec le même `code`, le même `message` et le même
    `data`, l'`id` de l'hôte. Un résultat que l'enregistreur rend lui-même
    (refus par la politique, signal d'approbation) a la forme d'EX-4.49.

**EX-4.19** Les pas 1 à 14 DOIVENT s'exécuter dans cet ordre ; en particulier
le pas 4 précède le pas 9 (aucun relais sans pièce « arguments » durable) et
le pas 13 précède le pas 14 (aucune réponse à l'hôte avant que l'événement soit
durable, sauf un appel de classe `lecture` en mode dégradé, section 14).

**EX-4.20** Les octets de `params.arguments` relayés au serveur et les octets
de `result` rendus à l'hôte sont ceux reçus, recopiés depuis le texte
d'origine, **blancs non significatifs exceptés** (EX-4.43) ; le frontal NE
DOIT PAS les resérialiser autrement (ordre des membres, échappements et
écriture des nombres sont conservés). Les pièces, elles, sont en JCS
intégral après rédaction (section 8) : la forme canonique n'est pas les
octets du réseau. Un nombre des arguments que la double précision ne
représente pas exactement est refusé avant tout relais (EX-4.44), de sorte
que la pièce et la politique voient la valeur sur laquelle le serveur agit ;
un tel nombre dans un résultat n'est pas conservé exactement dans la pièce
(section 8.1), tandis qu'il l'est dans les octets rendus.

**EX-4.43** **Cadrage et blancs.** JSON (RFC 8259) admet l'espace, la
tabulation, LF et CR comme blancs entre les jetons ; un texte JSON reçu en
Streamable HTTP peut donc contenir des sauts de ligne qu'un cadrage par
lignes lirait comme une fin de message. Le frontal DOIT retirer tous les
blancs non significatifs (U+0020, U+0009, U+000A, U+000D hors des chaînes)
de tout texte JSON qu'il recopie (arguments, `inputResponses`,
`requestState`, `result`, messages relayés hors chaîne), quel que soit le
transport de destination ; l'opération ne change aucune valeur, puisque le
JSON strict interdit CR et LF bruts dans une chaîne. Le connecteur stdio et
le démon DOIVENT rejeter par `-32700` toute ligne reçue d'un hôte qui
contient un CR, et ignorer en le consignant toute ligne de serveur d'outils
qui en contient un : le SDK MCP Python lit l'entrée standard en mode
« universal newlines », où CR termine une ligne (fichier
`src/mcp/server/stdio.py` du dépôt `modelcontextprotocol/python-sdk` et
documentation du module `io` de Python, lus le 2026-10-22), alors que le
connecteur ne découpe que sur LF. Sans cette règle, des arguments portant,
entre des sauts de ligne, un second message JSON-RPC complet seraient
exécutés par un serveur stdio comme un appel distinct, hors politique et hors
chaîne.

**EX-4.44** **Arguments exactement représentables.** Le frontal DOIT refuser
par `-32602`, avec `data: {"reason": "arguments_non_canonisables"}`, sans
relais, sans pièce et sans événement, un `tools/call` dont les arguments
contiennent un nombre que le JCS intégral ne sait pas écrire (hors de la
double précision IEEE 754, par exemple `1e400`) ; et avec `data: {"reason":
"nombre_non_representable"}` un `tools/call` dont un nombre a une valeur
décimale exacte différente de celle de sa forme JCS intégral (par exemple
`12345678901234567890`, dont la forme est `12345678901234567000`, ou
`0.10000000000000000001`, dont la forme est `0.1`). Un nombre comme `0.75`,
`1.0` ou `1e3` est admis : sa forme (`0.75`, `1`, `1000`) a la même valeur
décimale. La réponse d'erreur porte l'`id` de la requête, recopié depuis son
texte, pour `nombre_non_representable` ; pour `arguments_non_canonisables`,
elle porte `id: null`, l'analyse stricte s'arrêtant sur le nombre (un nombre
hors de la double précision ailleurs dans la requête donne la même erreur).
Motif : la politique (CT-3) et la pièce voient la valeur en double précision, le
serveur les octets ; un identifiant au-delà de 2^53 serait vu par la politique
comme un autre identifiant que celui sur lequel le serveur agit. Un client qui a
besoin de tels nombres les passe en chaînes, comme CT-1 §3 le demande pour les
montants.

**EX-4.45** **Définition servie et liste servie.** Le frontal DOIT tenir, par
connexion d'hôte, la **liste servie** : les définitions d'outils qu'il lui a
servies au dernier parcours complet de sa pagination `tools/list` (EX-4.13 ;
le parcours commence sans curseur et est servi depuis un instantané de la
liste agrégée). Pour un appel de nom annoncé `N`, `context` contient, dans
cet ordre (EX-7.7) : la pièce de la définition de `N` dans la liste servie ;
si la définition courante de `N` diffère (autre `sha256`), la pièce de la
définition courante ; puis la pièce **« liste annoncée »**, JCS intégral de
`{"tools": [<définitions de la liste servie, dans l'ordre servi>]}`, `kind:
"autre"`, `media_type: "application/json"`, qui prouve aussi ce que les
descriptions des autres outils disaient (empoisonnement par ombrage, R9
F-160, F-161). Si la connexion n'a jamais reçu de liste depuis le démarrage
du démon, ou si `N` n'y figure pas (liste mise en cache par l'hôte), la
définition courante et la liste agrégée courante en tiennent lieu, et le
fait est consigné (`definition_non_servie`). Une description piégée servie,
employée par le modèle puis remplacée juste avant l'appel, reste ainsi dans
la chaîne. `tools.definition_in_context: false` retire les pièces de
définition, `tools.list_in_context: false` la pièce de liste.

**EX-4.46** **Panne après relais.** Quand une panne survient après le pas 9
pour un appel déjà envoyé au serveur (stockage en erreur, signataire en
erreur ou signature invalide, bail perdu, horloge hors seuil, événement qui
échoue E-1 à E-7), le résultat est connu mais l'événement n'est pas
durable. Le frontal DOIT alors : rendre à l'hôte `-31017` (`noortrace: appel
execute, evenement non durable`, `data: {"intent_id": <intent_id ou null>,
"reason": <raison de la matrice de 14.2>}`), que l'agent ne peut pas lire
comme un refus ni comme une invitation à réessayer ; garder l'événement
complet (résultat compris) comme **événement en attente** (14.5), en mémoire
et, au mieux, dans le fichier d'attente ; le sceller à la sortie du mode
dégradé à la place d'un événement de reprise, et lever alors l'intention. Si
l'enregistreur s'arrête avant, l'intention restée ouverte donne l'événement
de reprise de 12.5 : c'est la perte admise (13.5). Le code `-31010`
(« appel bloque ») est réservé aux appels qui n'ont pas été relayés.

**EX-4.47** **Quotas par connexion d'hôte.** Chaque entrée de connexion
d'hôte porte, toutes requises par le schéma (valeurs de la configuration de
référence entre parenthèses), `quota.max_concurrent` (requêtes en cours,
32), `quota.piece_bytes_per_minute` (octets de pièces écrits pour elle par
minute glissante, 268 435 456), `quota.received_bytes_per_minute` (octets
reçus d'elle par minute glissante, requêtes refusées comprises,
268 435 456) et `quota.redaction_ms_per_minute` (temps de capture consommé
pour elle par minute glissante de l'horloge monotone, en millisecondes :
analyse JSON, rédaction sous la borne d'EX-10.23 et sérialisation des pièces
de ses requêtes, 30 000) ; au-delà, la requête est refusée au pas 1 par
`-31013` (`data.direction: "quota"`, avec `limit_requests`, `limit_bytes` ou
`limit_ms` selon le quota atteint) sans relais ni pièce, et consignée. Un
hôte ne peut ainsi ni remplir le volume du journal, ni faire entrer
l'enregistreur entier en mode dégradé « stockage » pour les autres hôtes, ni
occuper le calcul de l'enregistreur par la seule taille de ses requêtes :
une pièce réduite à la pièce non rédigeable (EX-10.23) n'écrit que
96 octets, mais son temps de capture est compté.

**EX-4.48** **Événement des issues sans réponse.** Dès que le pas 9 a commencé
(un octet est parti vers le serveur), **tout** appel, quelle que soit sa
classe, donne un événement `executee`, `is_error: true`, dont `duration_ms`
suit le pas 11 et dont la pièce « résultat » est la forme
`noortrace_jsonrpc_error` du code rendu (`-31011`, `-31012`, `-31013`,
`-31014`) ; une connexion impossible avant le pas 8 n'en donne aucun (pas 7).

**EX-4.21** `resultType: "input_required"` (MRTR, R1 Q5) : le résultat
intermédiaire est relayé tel quel au pas 14 et donne un événement comme tout
autre (pas 12 et 13, `is_error: false`) ; la ré-émission de l'hôte, avec un
nouvel `id`, `inputResponses` et `requestState`, est une nouvelle requête qui
repasse par le pas 1 et donne un second événement. Avant de relayer au pas 14
un résultat `input_required` qui porte un `requestState`, le noyau garde un
**enregistrement de continuation** : la connexion d'hôte, le nom annoncé, le
`sha256` du `requestState`, le MAC de relais des arguments en clair de
l'appel (EX-7.22), sa `policy`, son `approval`, son `intent` et son `code` ;
pour un appel qui porte l'approbation d'un ticket, il inscrit en outre dans
les fichiers des approbations la ligne `continuation` (ticket, `seq` et
`hash` de l'événement `executee` du pas 13, `sha256` du `requestState`) et
`fdatasync` avant le pas 14 (EX-12.23) : à la reprise ou après une bascule,
l'enregistrement d'un tel appel se reconstruit depuis cette ligne,
l'événement `executee` qu'elle désigne (`policy`, `approval`, `intent`,
`code`, nom) et la ligne `mac` de la `retenue` du ticket, égale au MAC de
l'appel puisqu'il a passé RL-2 ; celui d'un appel sans ticket est perdu.
Une ré-émission **hérite** de
l'appel d'origine sa `policy`, son `approval`, son `intent` et son `code` (CT-3
n'est pas rappelé, aucun nouvel événement `retenue` n'est produit :
l'approbation porte sur l'appel, pas sur chaque aller-retour MRTR) si et
seulement si :

1. son `requestState` a un enregistrement de continuation de la même
   connexion d'hôte et du même nom annoncé ;
2. le MAC de relais de ses arguments en clair est égal à celui de
   l'enregistrement : l'égalité des pièces « arguments » rédigées ne suffit
   pas, puisqu'un champ rédigé peut changer sans changer la pièce (deux IBAN
   différents donnent tous deux `[REDIGE:iban]`) ;
3. ce `requestState` n'a pas encore servi : chaque `requestState` hérite une
   fois, et l'usage est inscrit avant le relais (pour un ticket, ligne
   `continuation_consommee` et `fdatasync` avant le pas 8, sous la même
   exclusion que RL-3) — la spécification MCP ne garantit pas qu'un serveur
   refuse un `requestState` rejoué (CT-3 EX-11.10) ;
4. pour un appel qui porte un ticket approuvé, RL-1, RL-2, RL-3 en mode
   continuation et RL-4 passent (EX-7.21).

Toute autre ré-émission repasse par le pas 3, y compris celle dont
l'enregistrement a été perdu (redémarrage, pour un appel sans ticket) : la
politique voit alors ses arguments en clair, et une approbation déjà servie
ne la couvre pas (CT-3 EX-7.17) ; l'échec est fermé. Un `requestState` rejoué
N fois ne donne donc qu'un relais sous l'approbation, et un champ rédigé
changé n'hérite jamais d'une décision `autorise` ou `approuve` prise pour
d'autres arguments. `inputResponses` et
`requestState` n'entrent pas dans la pièce « arguments » (qui est
`params.arguments` seulement) ; le frontal ne les interprète pas, ne les
journalise pas en clair, et consigne leur `sha256` dans le journal
d'exploitation. Les `inputRequests` de type `sampling/createMessage` donnent un
échange de modèle (section 4.6). Limite de la version 0 : la réponse de
l'hôte à une elicitation, qui peut influer sur l'effet de l'outil, n'est pas
dans la chaîne.

**Délais, annulation, tailles.**

**EX-4.22** Chaque appel relayé a un délai `timeout_ms` (par outil dans la
configuration, sinon par serveur, sinon `tools.default_timeout_ms`, défaut
120 000). Au délai, le frontal annule l'appel amont (stdio :
`notifications/cancelled` avec le `requestId` amont ; HTTP moderne : fermeture
du flux de réponse, « Closing the SSE response stream is the cancellation
signal », page Cancellation 2026-07-28, R1 Q4 ; HTTP vers un serveur d'ère
héritée : `notifications/cancelled` **puis** fermeture du flux, puisque la
révision 2025-11-25 ne tient pas la déconnexion pour une annulation,
EX-4.23), scelle l'événement avec `is_error: true`, `duration_ms =
timeout_ms` (`t_reponse = t_envoi + timeout_ms`, pas 11) et la pièce
`{"noortrace_jsonrpc_error": {"code": -31011, "message": "noortrace: delai du
serveur d'outils depasse", "data": {"timeout_ms": N}}}`, et rend `-31011` à
l'hôte. Une réponse amont qui arrive après est ignorée et
notée. « Implementations SHOULD always enforce a maximum timeout, regardless of
progress notifications » (même page) : une progression ne prolonge pas le
délai.

**EX-4.23** Une annulation par l'hôte (stdio : `notifications/cancelled` ;
HTTP moderne : fermeture du flux de réponse) est relayée au serveur ; la
spécification 2025-11-25 ne tient pas la déconnexion pour une annulation
(« Disconnection SHOULD NOT be interpreted as the client cancelling », page
Transports 2025-11-25, R1 Q4) : pour un hôte hérité en HTTP, seule la
notification explicite annule. L'événement est scellé avec `is_error: true`,
`t_reponse` = l'instant d'envoi de l'annulation amont (pas 11),
et la pièce `{"noortrace_jsonrpc_error": {"code": -31012, "message":
"noortrace: appel annule par l'hote"}}` ; un appel de classe `ecriture` déjà
envoyé au serveur peut avoir produit son effet : l'événement le dit par
`effects` déclarés et `is_error: true`, et la réponse amont tardive, si elle
arrive, est consignée dans le journal d'exploitation avec son `sha256`.

**Codes d'erreur de l'enregistreur.** JSON-RPC 2.0 réserve `-32768` à
`-32000` aux erreurs prédéfinies et laisse le reste de l'espace des entiers
aux erreurs de l'application (https://www.jsonrpc.org/specification, §5.1,
R10 F-7). La révision `2026-07-28` partage `-32000` à `-32099` : `-32000` à
`-32019` sont hérités (aucun code nouveau n'y est alloué, une implémentation
nouvelle ne les emploie pas, et le récepteur ne leur suppose aucun sens, sauf
`-32002`) ; `-32020` à `-32099` sont réservés à la spécification, qui y
définit `-32020` (`HeaderMismatch`), `-32021`
(`MissingRequiredClientCapability`) et `-32022`
(`UnsupportedProtocolVersion`) ; `-32002` (`resource not found`, 2025-11-25
et antérieures, remplacé par `-32602`) et `-32042` (`URL elicitation
required`, 2025-11-25 seulement) restent réservés et ne sont plus émis ; un
code nouveau, pour un usage que la spécification ne définit pas, est pris
hors de `-32768` à `-32000` (page Overview, section « Error Codes »,
`docs/specification/2026-07-28/basic/index.mdx` L109-L155, R10 F-2 à F-4).
`-32001`, `-32003` et `-32004` n'ont existé que dans le brouillon de
2026-07-28 avant renumérotation (« HeaderMismatch -32001 → -32020,
MissingRequiredClientCapability -32003 → -32021, UnsupportedProtocolVersion
-32004 → -32022 »,
https://modelcontextprotocol.io/specification/2026-07-28/changelog, R1 Q9).

La spécification range les erreurs d'un appel d'outil en deux familles : les
erreurs de protocole (outil inconnu, requête mal formée, erreurs du serveur),
rendues comme des erreurs JSON-RPC, que les clients PEUVENT transmettre au
modèle ; les erreurs d'exécution (défaillance d'une API, validation des entrées,
logique métier), rendues dans un résultat `isError: true`, que les clients
DEVRAIENT transmettre au modèle (`server/tools.mdx` L738-L785, R10 F-9) ; le
schéma ajoute que toute autre « condition exceptionnelle » est une erreur MCP
(`schema.ts`, `CallToolResult.isError`, L1823-L1837, R10 F-10). CT-2 en
tire deux formes :

- l'issue d'une **politique d'approbation** (refus par la politique, ticket
  en attente, refusé ou expiré) est une erreur de logique métier de l'outil
  gardé, que le modèle doit voir pour ne pas répéter l'appel : c'est un
  **résultat** `isError: true` de texte fixe (EX-4.49), jamais une erreur
  JSON-RPC. Le `data` d'une erreur JSON-RPC n'atteint pas le modèle dans
  openai-agents 0.24.0 ni dans langchain-mcp-adapters 0.3.2, alors que le
  texte d'un résultat `isError` l'atteint dans ces deux bibliothèques et dans
  Claude Code (R10 F-22 à F-24) ; ce que Claude Code et les autres hôtes
  montrent au modèle d'une erreur JSON-RPC n'est pas vérifié (R10 F-24,
  NV-1) ;
- une **défaillance de l'enregistreur ou de l'amont** (mode dégradé, délai,
  annulation, taille, serveur injoignable, résultat non relayable, appel
  exécuté sans événement durable) est une condition exceptionnelle du
  mandataire : c'est une **erreur JSON-RPC**, de code pris hors de `-32768`
  à `-32000`. En faire un résultat `isError` la présenterait au modèle
  comme une erreur qu'il corrige en changeant ses arguments, alors que
  l'effet d'un appel d'écriture peut être incertain (EX-14.3). Un code de
  `-32000` à `-32019` n'aurait aucun sens pour le récepteur, sauf celui qu'on
  ne veut pas : un hôte relance l'appel sur `-32000` et `-32001`, et sur
  `408`, code local du SDK Python 1.x (R10 F-21, F-22).

Les codes de l'enregistreur gardent les deux derniers chiffres de la
version 0.2.

| Code | `message` (ASCII, fixe) | `data` | Émis quand |
|---|---|---|---|
| `-31010` | `noortrace: appel bloque, enregistreur en mode degrade` | `{"reason": …}` | Section 14 : stockage, clé ou bail indisponible pour un appel `ecriture` ou à approuver, horloge hors seuil, service d'approbation indisponible ou en défaut (raison `approbation`, EX-7.16, EX-7.17, EX-7.21), pièce « arguments » d'un appel `ecriture` ou susceptible d'approbation au-delà de la borne de temps (raison `redaction`, 4.4 pas 4, EX-10.23) |
| `-31011` | `noortrace: delai du serveur d'outils depasse` | `{"timeout_ms": N}` | EX-4.22 |
| `-31012` | `noortrace: appel annule par l'hote` | — | EX-4.23 (rendu seulement si l'hôte attend encore) |
| `-31013` | `noortrace: taille maximale depassee` | `{"limit_bytes": N, "direction": "requete" ou "reponse" ou "quota"}` ; pour un quota de temps ou de requêtes en cours, `{"limit_ms": N, "direction": "quota"}` ou `{"limit_requests": N, "direction": "quota"}` | Pas 1 et 11, EX-4.31, EX-4.47 |
| `-31014` | `noortrace: serveur d'outils injoignable` | `{"server": "<alias>"}` | Connexion amont impossible (pas 7, sans événement) ou perdue avant réponse (événement, EX-4.48) |
| `-31015` | non attribué | — | Jamais émis ni réattribué : l'ancien `-32015` (« approbation requise », version 0.2) est remplacé par le signal d'approbation (EX-4.49), qui n'est pas une erreur |
| `-31016` | `noortrace: resultat ou requete non relayable par la configuration` | `{"what": …}` | `resultType` inconnu ou `"task"`, requête serveur→client interdite (section 4.6) |
| `-31017` | `noortrace: appel execute, evenement non durable` | `{"intent_id": "…" ou null, "reason": …}` | Panne après le relais d'un appel (EX-4.46) |

**EX-4.24** Ces codes et messages sont fixes ; la section 14 et CT-3 les
réutilisent sans en créer d'autres sans mise à jour de cette table. Toute
erreur rendue par l'enregistreur lui-même DOIT être l'un de ces codes, ou un
code JSON-RPC standard (`-32700`, `-32600`, `-32601`, `-32602`, `-32603`) ou
de la spécification MCP (`-32020`, `-32021`, `-32022`) dans les cas que la
spécification prescrit. L'enregistreur NE DOIT émettre ni un code de
`-32000` à `-32019`, ni un code de `-32020` à `-32099` autre que ces trois,
ni `-32002`, ni `-32042`, ni un code de `100` à `599`. Une erreur reçue d'un
serveur d'outils, y compris un code hérité, ou `-32002` et `-32042` d'un
serveur d'ère héritée, est relayée telle quelle (pas 14) : ces codes ne sont
pas ceux de l'enregistreur. Le préfixe `noortrace:` de `message` distingue
une erreur de l'enregistreur d'une erreur relayée de même code ; qu'aucun
autre logiciel n'emploie `-31010` à `-31017` n'est pas vérifié (aucun
registre des codes d'application n'a été trouvé, R10 NV-3).

**EX-4.49** **Résultats rendus par l'enregistreur.** Deux résultats d'outil
sont produits par l'enregistreur lui-même, et non relayés d'un serveur : le
refus par la politique sans ticket (pas 5) et le **signal d'approbation**
(pas 5 et 6, EX-4.50). Chacun est un objet `CallToolResult` dont `content`
est un seul bloc `text` de texte ASCII fixe, avec `isError: true`, sans
`structuredContent` (qui devrait suivre l'`outputSchema` de l'outil gardé,
et que le SDK TypeScript 1.32.1 valide même pour une erreur, R10 F-12,
F-18), avec `_meta["io.modelcontextprotocol/serverInfo"]` (EX-4.4) et, pour
un hôte de l'ère moderne seulement, `resultType: "complete"`. Les membres
sont dans l'ordre des exemples ci-dessous. Le texte ne nomme jamais la règle
(CT-3 EX-11.8, 14.1). Pour la version `0.1.0` et un hôte de l'ère moderne,
le refus par la politique est exactement l'objet de CT-3 EX-11.8 :

```text
{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel refuse par la politique"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}
```

et le signal d'approbation du ticket `apr-1192` en attente est exactement :

```text
{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel soumis a approbation ; ticket=apr-1192 ; state=en_attente"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"},"noortrace/approval":{"ticket":"apr-1192","state":"en_attente"}}}
```

Le texte du signal est, sur une ligne, avec une espace de part et d'autre de
chaque `;` :

```text
noortrace: appel soumis a approbation ; ticket=<ticket> ; state=<state>
```

et `_meta["noortrace/approval"]` est exactement `{ "ticket", "state" }`,
avec `state` ∈ {`en_attente`, `refuse`, `expire`} selon la table de CT-3
EX-11.7 : le texte sert au modèle, la clé `_meta` aux programmes de l'hôte.
L'identifiant d'un ticket ne contient ni espace ni `;` (CT-3 EX-7.1). La clé
`noortrace/approval` suit la règle des clés `_meta` comme
`noortrace/delegation` (EX-7.2 ; un préfixe dont le second label est `mcp`
ou `modelcontextprotocol` est réservé, R10 F-13). Pour un hôte de l'ère
héritée, l'objet est le même sans `resultType`. Ces résultats ne sont pas
journalisés : l'événement `retenue` ou `refusee` de l'appel a `result: null`
(CT-1 §5.3). Le signal ne change pas le ticket ; la conduite qu'il appelle
de l'agent est celle de CT-3 EX-11.9.

**EX-4.50** **Mode `retenir`.** En mode `approval.mode: "retenir"`,
l'enregistreur retient **au plus une** requête de l'hôte par ticket : celle
qui a créé le ticket, ou, si elle a pris fin (délai, annulation par l'hôte),
la première ré-émission reconnue qui suit, dont le noyau calcule alors le MAC
de relais des arguments en clair (pas 3), que RL-2 compare à celui de la
`retenue` (EX-7.22) ; toute autre ré-émission reconnue
reçoit aussitôt le signal `en_attente`, sans événement (CT-3 EX-11.4). La
configuration DOIT fixer `hold_timeout_ms` inférieur d'au moins une seconde
au plus petit délai par appel de **tous** les hôtes raccordés, et ne choisir
ce mode que si la décision est attendue dans ce délai (CT-3 EX-11.2 ; pour
Claude Code, par exemple : en HTTP, 60 s par défaut jusqu'au premier octet
de la réponse ; en stdio, aucun minuteur par requête ; dans les deux cas,
abandon après `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` sans réponse ni
progression, 300 000 ms en réseau et 1 800 000 ms en stdio par défaut,
https://code.claude.com/docs/en/mcp, https://code.claude.com/docs/en/env-vars,
R7 F-25). À `hold_timeout_ms`, la requête reçoit le signal `en_attente` et le
ticket continue. Quand la décision du ticket est scellée pendant la
rétention (EX-7.19) : `approuve` → le noyau l'acquitte avec `held: true`,
relaie la requête retenue (pas 7 à 14, vérifications RL-1 à RL-4 comprises,
sans nouvelle évaluation) et envoie `consommer` (EX-7.20) ; `refuse` ou
`expire` → il scelle un événement `refusee` qui reprend la `policy` de
l'événement `retenue` et porte l'`approval` scellé (EX-7.12), et rend le
signal de même `state` (CT-3 EX-11.5). Pendant la rétention, l'enregistreur
PEUT envoyer à l'hôte des `notifications/progress` si la requête porte un
`progressToken`, à valeurs `progress` strictement croissantes, hors chaîne
(CT-3 EX-11.6) ; elles ne prolongent ni `hold_timeout_ms` ni l'échéance du
ticket.

**Différences d'ère.** Hôte hérité vers serveur moderne : le frontal ajoute
les `_meta` requis ; un `resultType: "input_required"` reçu du serveur ne peut
pas être rendu à un hôte hérité (qui ne connaît pas MRTR) : le frontal rend
`-31016` et consigne. Hôte moderne vers serveur hérité : le frontal fait
`initialize` à la connexion ; une requête du serveur vers le client
(`sampling/createMessage`, `elicitation/create`, `roots/list`) arrive comme
vraie requête JSON-RPC sur le flux amont ; le frontal ne peut pas la convertir
en MRTR pour l'hôte (il faudrait répondre `input_required` à une requête déjà
partie), il la sert donc en répondant au serveur une erreur `-32601` et
consigne, sauf `roots/list` qu'il sert depuis la configuration (`roots`
statiques) si elle en donne. Hôte hérité vers serveur hérité : les requêtes
serveur→client sont relayées dans les deux sens (section 4.6).

### 4.5 Autres méthodes, relayées hors chaîne

**EX-4.25** Les méthodes `resources/list`, `resources/templates/list`,
`resources/read`, `prompts/list`, `prompts/get`, `completion/complete`, et, en
ère héritée, `resources/subscribe`, `resources/unsubscribe`,
`logging/setLevel` et `ping`, ainsi que les notifications associées, sont
relayées si et seulement si la configuration l'autorise (`relay.resources`,
`relay.prompts`, `relay.completions`, chacun `false` par défaut), et ne
produisent **aucun événement** : limite de la version 0, dite ici en clair.
Chaque relais est consigné dans le journal d'exploitation avec la méthode,
l'alias, l'`id` d'hôte, l'`id` amont, la taille des `params` et du `result` et
leur `sha256` en JCS intégral (sans la valeur).

**EX-4.26** Les noms de prompts sont préfixés comme les noms d'outils
(EX-4.10, EX-4.11). Les URI de ressources ne sont pas réécrites : une requête
`resources/read` est routée vers le serveur dont la configuration déclare un
préfixe d'URI correspondant (`resources.uri_prefixes`), ou vers l'unique
serveur si un seul est configuré ; sans correspondance, `-32602`. Les
collisions de préfixes d'URI sont une erreur de configuration (comme les
collisions de noms chez Docker MCP Gateway, R9 F-12).

**EX-4.27** `logging/setLevel` et `notifications/message` : l'enregistreur ne
déclenche jamais lui-même de journalisation MCP (dépréciée en 2026-07-28, R1
Q4) ; il relaie ce que l'hôte demande et ce que le serveur émet pour la
requête concernée. Son propre journal va sur `stderr` (stdio) et dans le
journal d'exploitation.

### 4.6 Requêtes du serveur vers le client

En ère moderne, « Servers MUST NOT initiate JSON-RPC requests » (page Patterns
2026-07-28, R1 Q5) : `roots/list`, `sampling/createMessage` et
`elicitation/create` voyagent dans un `InputRequiredResult` et la réponse de
l'hôte dans la ré-émission. En ère héritée, le serveur émet de vraies requêtes
JSON-RPC sur le flux SSE de la requête ou sur le flux GET (HTTP) ou sur
`stdout` (stdio), et le client répond par une réponse JSON-RPC (R1 Q5).

**EX-4.28** La configuration fixe, par serveur, ce qui peut être relayé :
`relay.server_requests.sampling` (défaut `false`), `.elicitation` (défaut
`false`), `.roots` (défaut `false` : la fonctionnalité est dépréciée et expose
des chemins de fichiers de l'hôte) ; `policy.servers.<alias>.relay` les
active serveur par serveur. Motif des défauts : l'hôte ne voit qu'un serveur,
l'enregistreur ; un `sampling` relayé obtiendrait sous son identité le
contexte de tous les serveurs agrégés, et une elicitation paraîtrait venir de
l'enregistreur. Un `sampling/createMessage` relayé porte toujours
`includeContext: "none"` vers l'hôte, quelle que soit la valeur demandée par
le serveur (option dépréciée mais encore présente, R1 Q5), et la valeur
demandée est consignée. Le `message` d'une `elicitation/create` relayée est
préfixé par `[<alias>] ` (alias du serveur qui l'émet), pour que
l'utilisateur sache quel serveur demande. Une capacité non relayable n'est pas
déclarée au serveur (EX-4.7) ; si le serveur l'emploie quand même (« Servers
MUST NOT send an `inputRequests` that the client has not declared support
for », page MRTR, R1 Q5), le frontal rend `-31016` à l'hôte, répond `-32601`
au serveur en ère héritée, et consigne.

**EX-4.29** Un `sampling/createMessage` relayé est un **échange de modèle** :
l'enregistreur produit un événement `noortrace.modele.echange` (section 7.2)
dont la pièce « requête » est l'objet `params` de `CreateMessageRequest`
(`messages`, `systemPrompt`, `modelPreferences`, `maxTokens`, `tools`,
`toolChoice`, … tels que reçus) rédigé et sérialisé en JCS intégral, la pièce
« réponse » est l'objet `CreateMessageResult` (`role`, `content`, `model`,
`stopReason`) rédigé et sérialisé de même, `code.model = "hote/" +
CreateMessageResult.model` (le fournisseur réel est inconnu de
l'enregistreur : c'est l'hôte qui a servi le modèle), `duration_ms` = temps
entre l'envoi de la requête à l'hôte (ère héritée) ou du résultat
`input_required` (ère moderne) et la réception de la réponse ou de la
ré-émission, `is_error = false`. Si l'hôte refuse ou ne répond pas, aucun
événement n'est produit (il n'y a pas eu d'échange) ; le refus est consigné.
`CreateMessageResult.model` est « The name of the model that generated the
message » (`schema.ts` 2026-07-28, R1 Q5).

**EX-4.30** `elicitation/create` est relayée hors chaîne (section 4.5) ; le
journal d'exploitation reçoit le mode (`form` ou `url`), le `sha256` du
`requestedSchema` et celui du `content` rendu, jamais le `content`. En mode
`url`, le frontal relaie l'URL sans la préfixer ni la visiter (« MUST NOT
automatically pre-fetch the URL », page Elicitation, R1 Q5). `roots/list` est
relayée hors chaîne si autorisée.

### 4.7 Transports

#### 4.7.1 stdio

**EX-4.31** Cadrage : un message JSON-RPC par ligne, terminé par `\n`, encodé
en UTF-8, sans saut de ligne interne ; rien d'autre sur `stdout` ; le journal
de l'enregistreur sur `stderr` (page stdio 2026-07-28 et 2025-11-25, R1 Q6).
Le connecteur et le démon n'acceptent **que** ce cadrage ; une entrée cadrée
par `Content-Length` (rencontrée chez certains mandataires, R9 F-111) est
refusée et consignée ; une ligne qui contient un CR est rejetée (EX-4.43) ;
une ligne de plus de `limits.line_max_bytes` octets (défaut
`limits.request_max_bytes` + 65 536) est refusée par `-31013` et la lecture
reprend après le `\n` suivant. Le même cadrage est employé entre le
connecteur et le démon, sur une prise de domaine Unix ou une prise TCP locale
(« The wire format […] works unchanged over Unix domain sockets, TCP
connections », page stdio 2026-07-28, R1 Q6), et par les serveurs d'outils
stdio lancés par le démon. Une prise TCP n'a pas d'identité de pair : elle
exige un jeton ou mTLS (EX-4.39).

**EX-4.32** La sortie d'erreur d'un serveur d'outils stdio est lue ligne par
ligne par le démon et NE DOIT PAS être interprétée comme une erreur
(« SHOULD NOT assume `stderr` output indicates error conditions », même page).
Elle n'est pas relayée à l'hôte. Elle est consignée dans le journal
d'exploitation sous `child_stderr` avec l'alias, mais, par défaut
(`supervision.ops_log.child_stderr: "empreinte"`), seulement par sa longueur
et son `sha256` : un serveur peut y écrire des secrets ou des données
personnelles, ce qu'EX-9.6 interdit au journal d'exploitation. La valeur
`"texte"` consigne la ligne, tronquée à `child_stderr_max_bytes`, après
application des détecteurs de texte de la portée `resultat` ; elle se règle
par serveur et la validation l'affiche comme un avertissement. Le débit est
borné à `supervision.ops_log.child_stderr_lines_per_second` (défaut 20) par
serveur ; les lignes au-delà sont comptées, pas consignées, pour qu'un
serveur ne puisse pas faire tourner le journal d'exploitation et effacer une
trace comme `tool_definition_changed`.

**EX-4.33** Si un serveur d'outils stdio se termine, le frontal le relance
selon `restart.max_attempts` et `restart.backoff_ms` ; les appels en vol vers
lui, de **toute classe**, reçoivent `-31014` et leur événement `is_error:
true` (EX-4.48 ; `t_reponse` = instant où la fin du processus ou de sa sortie
standard est constatée) ; en ère moderne « any in-flight requests are simply
lost and the client can retry them » (page stdio 2026-07-28, R1 Q2).

#### 4.7.2 Streamable HTTP

**EX-4.34** Le frontal expose un seul chemin, `/mcp` par défaut, qui accepte
POST ; en ère moderne, GET et DELETE reçoivent `405 Method Not Allowed`, un
en-tête `Mcp-Session-Id` est ignoré sans jamais être frappé ni renvoyé, un
`Last-Event-ID` est ignoré (page Streamable HTTP 2026-07-28, section
« Backwards compatibility », R1 Q7). Il valide `Origin` et répond `403` à une
origine présente et invalide, se lie à `127.0.0.1` par défaut, et exige une
authentification (section 4.8) sur **toute** connexion, locale comprise :
`127.0.0.1` est joignable par tout processus de la machine.

**EX-4.35** Ère moderne, requête : `Accept` listant `application/json` et
`text/event-stream` ; en-tête `MCP-Protocol-Version` égal à
`_meta["io.modelcontextprotocol/protocolVersion"]`, sinon `400` et
`-32020` (`HeaderMismatch`) ; en-têtes `Mcp-Method` (toutes requêtes) et
`Mcp-Name` (`tools/call`, `resources/read`, `prompts/get`) égaux au corps,
sinon `400` et `-32020` ; `Mcp-Param-*` validés contre les paramètres
`x-mcp-header` de la définition d'outil quand ils sont définis ; sentinelle
`=?base64?…?=` décodée avant comparaison (page Streamable HTTP 2026-07-28,
R1 Q7). Vers le serveur, le frontal **construit** ces en-têtes d'après le
corps relayé et la définition courante de l'outil (`Mcp-Name` porte le nom
d'origine ; un `Mcp-Param-*` pour chaque paramètre `x-mcp-header` de la
définition présent dans les arguments) et n'en recopie aucun de l'hôte. La
page dit : « Intermediate servers that do not recognize an `Mcp-Param-{Name}`
header MUST forward it » ; le frontal n'est pas un intermédiaire transparent
au sens de cette phrase : il est le serveur de l'hôte et le client du serveur
d'outils, il connaît la définition qu'il a servie, et un `Mcp-Param-*` de
l'hôte qui n'y correspond à aucun paramètre est ignoré et consigné. Les
autres en-têtes vers le serveur suivent la liste d'EX-4.41. Une notification
reçoit `202 Accepted` sans corps ; une méthode inconnue, `404` et `-32601`.

**EX-4.36** Réponse en flux : si le serveur répond en `text/event-stream`, le
frontal répond à l'hôte en `text/event-stream` et relaie **chaque événement
SSE dès réception**, sans tampon, avec l'en-tête `X-Accel-Buffering: no` ; il
émet un commentaire SSE (`:` seul) toutes les 15 secondes d'inactivité pour
tenir la connexion ; la réponse JSON-RPC finale clôt le flux (« The final
JSON-RPC response SHOULD terminate the stream », R1 Q7). La fermeture du flux
par l'hôte vaut annulation (EX-4.23). Aucune reprise par `Last-Event-ID` : le
frontal n'émet pas d'`id` d'événement SSE et, en ère héritée, décline la
reprise (`Servers MAY attach an id`, R1 Q7 : facultatif) ; un flux coupé perd
la requête en vol, que l'hôte ré-émet.

**EX-4.37** Ère héritée vers l'hôte : le frontal frappe un `Mcp-Session-Id`
(au moins 128 bits aléatoires, caractères ASCII visibles) dans la réponse à
`initialize`, exige l'en-tête sur toute requête suivante (`400` sans lui),
répond `404` après avoir terminé la session (l'hôte réinitialise), honore
`DELETE`, sert le flux GET pour les notifications et les requêtes
serveur→client relayées, et envoie chaque message sur un seul flux (règles de
la page Transports 2025-11-25, R1 Q7). Sans en-tête `MCP-Protocol-Version`,
il suppose `2025-03-26` (même page).

**EX-4.38** Ère héritée vers un serveur : le frontal conserve le
`Mcp-Session-Id` reçu et le renvoie sur chaque requête, ouvre un flux GET pour
recevoir les requêtes serveur→client et les notifications, réinitialise sur
`404`, envoie `DELETE` à l'arrêt. Les sessions amont n'apparaissent jamais dans
la chaîne : la corrélation repose sur les `id` JSON-RPC, les jetons de
progression et, pour le MRTR, sur le couple (requête, ré-émission) (R1,
conséquence 2).

### 4.8 Authentification

**Hôte → enregistreur.** **EX-4.39** En stdio, aucune authentification de
protocole (« implementations using STDIO transport SHOULD NOT follow this
specification, and instead retrieve credentials from the environment », page
Authorization, R1 Q8) : l'identité de la connexion d'hôte est celle du
processus connecteur, lue par le démon sur la prise locale (identifiant
d'utilisateur du pair), et la configuration lui associe une délégation
(section 7.2). En Streamable HTTP, le frontal est un **serveur de ressources
OAuth 2.1** : il publie ses métadonnées de ressource protégée (RFC 9728) à
`/.well-known/oauth-protected-resource/mcp`, renvoie `401` avec
`WWW-Authenticate: Bearer resource_metadata="…"` et `scope`, n'accepte que des
jetons dont l'audience est son URI canonique (RFC 8707), rend `401` à un jeton
invalide ou expiré et `403` à une portée insuffisante (page Authorization
2026-07-28, R1 Q8). Pour les hôtes qui ne savent envoyer qu'un en-tête fixe
(Cursor `headers`, Claude Code `--header`, R7 F-18, F-46), la configuration
PEUT déclarer des **jetons statiques par hôte** (référence de secret, jamais la
valeur) comparés en temps constant ; un jeton statique vaut identité de
connexion d'hôte comme un jeton OAuth. Une **prise TCP** entre connecteur et
démon (ou du SDK) n'a pas d'identité de pair : elle DOIT exiger un jeton
statique (première ligne du connecteur : `{"noortrace_token": "<jeton>"}`,
comparée en temps constant, puis retirée) ou mTLS ; en `environment:
"production"`, une prise TCP sans l'un des deux est refusée par la validation.
Sous Windows, l'identité du pair d'un tube nommé n'est pas traitée en version
0 (non vérifié) : la prise TCP avec jeton est la seule forme admise.

**Enregistreur → serveur d'outils.** **EX-4.40** L'enregistreur s'authentifie
auprès de chaque serveur d'outils avec **ses propres identifiants**, nommés par
alias dans la configuration : en-têtes statiques (référence de secret), ou
client OAuth 2.1 (identifiants préenregistrés, ou Client ID Metadata Document
publié par l'enregistreur, DCR en repli parce que déprécié, PKCE `S256`
obligatoire, `resource` RFC 8707 = URI canonique du serveur, validation de
`iss`, identifiants liés à l'`issuer`), selon la page Authorization 2026-07-28
(R1 Q8). Pour un serveur stdio, les identifiants vont dans l'environnement du
processus enfant, depuis des références de secrets. La découverte OAuth suit
des URL fournies par le serveur (`resource_metadata`,
`authorization_servers`) ; la page « Security Best Practices » demande d'y
tenir compte du risque de falsification de requête côté serveur (SSRF) et
recommande de bloquer les plages privées et réservées (R1 Q8). En
`environment: "production"`, la configuration DOIT épingler, pour chaque
serveur OAuth, l'émetteur et l'URL de ses métadonnées
(`transport.oauth.issuer`, `transport.oauth.resource_metadata_url`), et le
démon n'en suit pas d'autres ; à défaut d'épinglage (développement), il
n'admet que HTTPS, une URL de métadonnées de même origine que le serveur,
aucune redirection, et refuse toute adresse résolue dans `0.0.0.0/8`,
`10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`,
`172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7` et `fe80::/10`
(liste de cette spécification).

**EX-4.41** **Aucun relais de jeton.** Le frontal NE DOIT PAS transmettre à un
serveur d'outils un jeton reçu de l'hôte, ni accepter de l'hôte un jeton émis
pour un autre destinataire : « MCP servers MUST NOT accept or transit any
other tokens » et « The MCP server MUST NOT pass through the token it received
from the MCP client » (pages Authorization et Security Considerations
2026-07-28, R1 Q8 ; « Token passthrough » des Security Best Practices, R9
F-152). Les en-têtes `Authorization`, `Cookie` et tout en-tête nommé dans
`auth.strip_headers` reçus de l'hôte ne sont jamais relayés ni journalisés,
pas même dans le journal d'exploitation. Plus largement, le frontal MCP
n'envoie au serveur d'outils **que** les en-têtes qu'il construit : ceux de la
requête MCP (EX-4.35), `Content-Type`, `Accept`, les en-têtes
d'authentification propres de l'enregistreur (EX-4.40) et les en-têtes
statiques de la configuration du serveur ; aucun en-tête de l'hôte n'est
recopié (liste autorisée, pas liste de refus), et le cadrage
(`Content-Length`, `Transfer-Encoding`) est calculé par l'enregistreur sur
les octets qu'il envoie, jamais recopié.

**EX-4.42** Quand l'enregistreur agit comme client OAuth statique pour le
compte de plusieurs hôtes, il DOIT tenir un registre des `client_id` consentis
par utilisateur et le consulter avant tout flux d'autorisation tiers (confused
deputy : « MCP proxy servers MUST implement per-client consent », R1 Q8, R9
F-151). Les identifiants de tiers ne transitent jamais par l'hôte.

### 4.9 Ce que l'agent ne peut pas faire, et ce que le client doit faire

Ce que l'agent ne peut pas faire quand les règles de cette section sont
appliquées : atteindre un serveur d'outils sans passer par l'enregistreur
(EX-4.1) ; se faire passer pour l'enregistreur auprès d'un serveur d'outils
(il n'a pas ses identifiants, EX-3.2, EX-4.40) ; obtenir un résultat d'un appel
d'écriture sans qu'un événement durable existe (EX-4.19) ; faire disparaître la
définition d'un outil qui l'a trompé (EX-4.16) ; réutiliser un jeton d'hôte
contre un serveur d'outils (EX-4.41).

Ce que l'agent peut encore faire, et que l'enregistreur ne prétend pas
empêcher : déclarer une fausse délégation dans `_meta` (déclaratif, section
7.2) ; répéter un appel ; agir par un canal qui n'est ni MCP ni une API de
modèle configurée. Ce qui ne traverse pas l'enregistreur n'est pas
journalisé : aucun dossier ne peut prouver un acte qui n'a pas été capturé
(section 21).

Ce que le client doit faire sur son réseau :

1. **Filtrer la sortie par nom plutôt que par adresse.** Les règles
   d'application d'Azure Firewall et les listes de domaines d'AWS Network
   Firewall lisent le SNI ou l'en-tête `Host` sans déchiffrer (R4 F1.7.5,
   F1.7.6) ; les objets FQDN de PAN-OS et de FortiGate reposent sur la
   résolution DNS et dépendent donc du serveur DNS du client (R4 F1.7.3,
   F1.7.4). Anthropic publie des plages d'adresses fixes (`160.79.104.0/23`
   entrant, R4 F1.7.1) ; OpenAI ne publie pas de plages d'entrée sur les
   pages lues (R4 F1.7.2, N2.10) : les plages servent de complément, pas de
   règle principale.
2. **N'autoriser que le démon** à joindre les serveurs d'outils HTTP et les
   fournisseurs de modèle (section 5.1) ; refuser ces destinations au réseau
   des hôtes et des agents.
3. **Isoler le stockage** du journal sur un volume que ni l'hôte ni l'agent ne
   montent (section 12, 18).
4. **Donner au démon son utilisateur système**, et lancer chaque serveur
   d'outils stdio sous un utilisateur distinct, sans droit sur le stockage
   ni sur les secrets du démon, dans un conteneur ou un bac à sable (EX-3.4,
   EX-3.5).
5. **Journaliser au pare-feu** les tentatives de connexion directe des
   réseaux d'hôtes vers les serveurs d'outils et les fournisseurs : ce sont les
   contournements que l'enregistreur ne voit pas.

## 5. Frontal modèle

### 5.1 Modes et justification de la passerelle

| Mode | Principe | Peut bloquer | Ce qu'il exige du client | Force de la preuve |
|---|---|---|---|---|
| `passerelle` (nominal) | L'hôte adresse ses requêtes d'API de modèle à l'enregistreur par l'URL de base de son SDK ; l'enregistreur les relaie au fournisseur | Oui (il est sur le chemin) | Une variable d'environnement ou un réglage par hôte ; un pare-feu de sortie qui n'autorise que l'enregistreur à joindre les fournisseurs | Forte avec le pare-feu |
| `icap` | Le mandataire HTTPS existant du client déchiffre et soumet requêtes (REQMOD) et réponses (RESPMOD) à l'enregistreur par ICAP, RFC 3507 | Les requêtes oui (REQMOD) ; les réponses en flux non (5.1.2) | Un mandataire déjà en place avec interception TLS et client ICAP ; l'autorité de certification d'interception sur les postes | Forte si l'hôte ne peut pas contourner le mandataire |
| `miroir` | Un équipement du client copie le trafic déchiffré vers un adaptateur qui le remet à l'enregistreur | Non | Un pare-feu qui sait produire une copie déchiffrée et, selon l'éditeur, un avis juridique (recommandé par Palo Alto Networks) ou un accord juridique accepté à l'activation (Fortinet) (R4 F1.4.1, F1.4.6, F1.4.7) | Preuve en lecture seule |
| `desactive` | Aucune capture de modèle ; seuls les appels d'outils sont journalisés | — | — | `code.model`, `intent`, `prompt_version` sont `null` |

**EX-5.1** La configuration DOIT nommer le mode du frontal modèle parmi
`passerelle`, `icap`, `miroir`, `desactive` ; `passerelle` est la valeur
recommandée et celle de la démonstration de référence (section 19).

**Pourquoi la passerelle devient le mode nominal.** L'architecture cible ne
parlait que de l'interception TLS par le mandataire de sortie du client. Les
faits établis par les digests conduisent à inverser l'ordre :

1. **Reconfigurer un SDK coûte une variable d'environnement.** Les quatre SDK
   officiels lisent une URL de base dans l'environnement : `ANTHROPIC_BASE_URL`
   (SDK Python `_client.py`, SDK TypeScript `client.ts`, R2 F-S1, F-S2) et
   `OPENAI_BASE_URL` (SDK Python et Node, R2 F-S3, F-S4). Claude Code la lit
   aussi (`ANTHROPIC_BASE_URL`, avec `ANTHROPIC_AUTH_TOKEN` ou
   `ANTHROPIC_API_KEY`, R7 F-30, F-31), le SDK Agents d'OpenAI en Python
   (`OPENAI_BASE_URL`, R7 F-61) et LangChain (`ChatOpenAI`, `ChatAnthropic`,
   R7 F-80, F-81). LiteLLM, Portkey, Helicone et Cloudflare AI Gateway se
   branchent par l'URL de base du SDK (R4 F1.6.1 à F1.6.8) ; Kong AI Gateway
   et Azure APIM exposent aussi des points d'API aux formats d'OpenAI ou
   d'Anthropic (R4 F1.6.11, F1.6.13) : c'est le mode d'intégration le moins
   intrusif.
2. **L'interception TLS coûte trois injections de confiance et un piège Node.**
   La racine d'interception doit être placée dans le magasin système, dans les
   variables des piles HTTP (`SSL_CERT_FILE`/`SSL_CERT_DIR` pour httpx et Go,
   `REQUESTS_CA_BUNDLE` pour requests, `NODE_EXTRA_CA_CERTS` ou
   `NODE_USE_SYSTEM_CA=1` pour Node) et en exceptions pour les applications à
   épinglage (R4 C3.7) ; Node.js n'honore `HTTPS_PROXY` qu'avec
   `NODE_USE_ENV_PROXY=1` (Node v24.0.0 et v22.21.0 ou plus),
   `--use-env-proxy` (v24.5.0 et v22.21.0 ou plus) ou un `dispatcher` undici
   (`EnvHttpProxyAgent`, `ProxyAgent`) enregistré explicitement
   (https://nodejs.org/api/cli.html, R4 F1.8.4, F1.8.5 ; R2 F-S11), alors
   que le SDK TypeScript d'Anthropic accepte Node 20 (R4 F1.5.11).
3. **Un flux SSE se relaie sans tampon par la passerelle, pas par ICAP.** ICAP
   exige le codage `chunked` et ne connaît pas la longueur d'avance ; un
   verdict entier n'est possible qu'après réception complète, sauf `204` au
   Preview, qui dispense le client d'envoyer le corps et laisserait
   l'enregistreur sans réponse à journaliser (RFC 3507, R4 F1.1.4, F1.1.5,
   F1.1.9, C3.1 ; EX-5.5) ; Squid refuse un `204`
   au-delà de 64 Ko ou quand la taille est indéterminable (R4 F1.2.4) ; le
   « trickling » de Check Point ne fonctionne pas sans `Content-Length` (R4
   F1.3.11). Claude Code exige que la passerelle ne tamponne pas et relaie les
   `ping` SSE (R7 F-35). Une passerelle relaie chaque événement dès réception.
4. **Les en-têtes et le corps traversent intacts.** La passerelle voit la
   requête complète ; le miroir ne voit qu'une copie et ne peut rien
   bloquer ; ICAP voit requête et réponse mais séparément (5.1.2).

Ce que la passerelle ne résout pas : un hôte qui ne sait pas changer d'URL de
base. L'application Claude Desktop standard n'offre pas de réglage documenté
(R7 NV-05) ; seul le mode de déploiement « Claude Desktop on 3P » route
l'inférence vers une passerelle (`inferenceProvider: "gateway"`,
`inferenceGatewayBaseUrl`, R7 F-91). Cursor ne documente pas d'option d'URL de
base (R7 NV-02). Pour ces hôtes, le mode `icap` est l'alternative, le mode
`miroir` la preuve passive, et le frontal MCP capture dans tous les cas les
appels d'outils.

#### 5.1.1 Mode passerelle

**EX-5.2** La passerelle écoute sur l'URL de base configurée (`model.listen`,
TLS par le client ou par un mandataire inverse devant le démon) et sert les
**routes** de la configuration (`policy.model.routes`, membre de l'ensemble de
politique : changer une route change ce que le journal prouve) : chaque route
associe un **chemin exact** (`/v1/messages`, `/v1/chat/completions`,
`/v1/responses`, ou le chemin d'une variante d'hébergeur) et la méthode `POST`
à un format de la version 0 (5.2), à l'URL amont du fournisseur, à ses
identifiants et à un libellé de fournisseur pour `code.model`. Le chemin de
la requête est d'abord **normalisé** : une requête dont le chemin contient
`%2F` ou `%2f`, un segment `.` ou `..`, une barre oblique doublée, ou un
octet hors de l'ASCII imprimable, est refusée par `400` ; les encodages
pourcent de caractères non réservés sont décodés (RFC 3986 §6.2.2) ; le
chemin normalisé est comparé **par égalité** à ceux des routes (jamais par
préfixe). La chaîne de requête (`?beta=true`) est relayée telle quelle et
consignée par son `sha256`, jamais interprétée. Vers l'amont, la passerelle
n'envoie que le chemin de la route trouvée, pas le texte reçu. Chaque route
porte en outre une liste **exacte** de couples relayés **sans événement**,
`passthrough: [{ "method": "POST", "path": "/v1/messages/count_tokens" },
{ "method": "GET", "path": "/v1/models" }]` (chemins que Claude Code peut
appeler, R7 F-33, F-37), servis avec l'amont et les identifiants de la route
et consignés ; liste vide par défaut. Tout autre couple (méthode, chemin)
reçoit `404` sans relais : les lots, fichiers et plongements d'un fournisseur
ne traversent pas la passerelle hors capture, puisqu'ils ne sont relayés que
s'ils sont nommés.

#### 5.1.2 Mode ICAP

**EX-5.3** En mode `icap`, le démon est un serveur ICAP (RFC 3507) qui expose
deux services sur deux URI, `icap://<hôte>:1344/noortrace/reqmod` et
`icap://<hôte>:1344/noortrace/respmod` (un service par méthode, R4 F1.2.1),
et ICAPS sur 11344 (R4 F1.2.1, F1.3.2, F1.3.3). Il répond à `OPTIONS` avec les
en-têtes obligatoires `Methods`, `ISTag` et `Encapsulated: null-body=0`
(« MUST be included in the OPTIONS response », RFC 3507 §4.10.2), plus
`Options-TTL`, et n'annonce pas de `Preview` ; toute réponse ICAP porte
`ISTag` (« The ISTag MUST be included in every ICAP response from an ICAP
server », §4.7 ; https://www.rfc-editor.org/rfc/rfc3507). Hors Preview, la
permission de répondre `204` est donnée par le client ICAP, requête par
requête, par son en-tête `Allow: 204` ; en réponse à un Preview, `204` est
toujours permis, « EVEN if the original request did not have the "Allow: 204"
header » (§4.6, R4 F1.1.6). **Authentification des clients ICAP** : le
démon n'accepte de transaction que d'un mandataire authentifié, par ICAPS
avec certificat client (mTLS, `model.icap.client_ca`) ou, sur un lien
maîtrisé, par une liste d'adresses sources autorisées
(`model.icap.allowed_sources`) ; en `environment: "production"`, l'une des
deux est exigée par la validation. Une machine du réseau ne peut ainsi pas
soumettre des transactions fabriquées qui deviendraient des échanges signés.

**EX-5.4** REQMOD : l'enregistreur lit la requête HTTP encapsulée (`req-hdr`,
`req-body`), retire tout en-tête `X-Noortrace-*` reçu, construit les pièces
« requête » et « prompt système », évalue le format (5.2), puis rend une
requête **modifiée** (`200`) identique à l'originale augmentée de l'en-tête
`X-Noortrace-Exchange: <i>.<m>`, où `<i>` est un identifiant aléatoire de 128
bits et `<m>` les 128 premiers bits de HMAC-SHA-256(clé éphémère du démon,
`<i>`), en hexadécimal minuscule ; il NE DOIT PAS rendre `204` sur REQMOD.
RFC 3507 ne définit aucun identifiant de transaction entre REQMOD et RESPMOD.
RESPMOD encapsule, si le client ICAP le fait (« If available, the header of
the original client request SHOULD also be included », §4.9.1,
https://www.rfc-editor.org/rfc/rfc3507), l'en-tête de la requête d'origine ;
que cet en-tête soit la requête **adaptée** par REQMOD, porteuse de
`X-Noortrace-Exchange`, n'est documenté pour aucun des mandataires lus (R4 :
Squid, ProxySG, FortiGate, Check Point) et sera vérifié sur Squid en phase 2.
L'enregistreur n'admet en RESPMOD qu'un `X-Noortrace-Exchange` dont le MAC
vérifie et qu'il a émis lui-même ; à défaut, il corrèle par (méthode, URI,
en-têtes de la requête, instant), ce qui peut échouer : un RESPMOD sans
REQMOD retrouvé donne un échange dont la pièce « requête » est
`{"noortrace_requete_inconnue": true}`, consigné. L'enregistreur bloque en
REQMOD dans deux cas seulement : une requête refusée par EX-5.7 (corps non
analysable, `Content-Encoding`) et un mode dégradé bloquant pour les échanges
de modèle (14.2) ; il rend alors une réponse HTTP encapsulée (`res-hdr`,
`res-body`) au statut et au corps d'EX-5.7 ou de 14.2, et **aucun événement**
n'est scellé, puisque rien n'a atteint le fournisseur (le blocage est
consigné).

**EX-5.5** RESPMOD : l'enregistreur répond `100 Continue` à un Preview (ou le
client n'en envoie pas, puisque `OPTIONS` n'en annonce pas), lit le corps et
rend le message inchangé (`200`, `Encapsulated: res-hdr=0, res-body=…`)
chunk par chunk, au fil de la réception, sans tampon ; il **ne répond jamais
`204` en RESPMOD**, puisqu'un `204` après un Preview dispense le client
d'envoyer le corps (« The ICAP client MUST treat this the same as if it had
sent the entire message to the ICAP server and an identical message was
returned », RFC 3507 §4.5) et laisserait l'événement sans pièce « réponse »
(R4 F1.1.9 ; Squid n'accepte pas de `204` hors Preview pour une charge de
taille indéterminable, R4 F1.2.4). En RESPMOD, il ne bloque jamais une
réponse en flux : la réponse est déjà en route. Le
mandataire du client DOIT déchiffrer avant d'adapter (condition de tous les
équipements lus : ProxySG, FortiGate, Check Point, Squid `ssl_bump`, R4 F1.2.6,
F1.3.3, F1.3.6, F1.3.9) et appliquer le service à la seule destination des
fournisseurs de modèle ; chez Squid, un seul service d'adaptation par point de
vectorisation (R4 F1.2.2) : un antivirus RESPMOD déjà en place impose un
chaînage, documenté en section 19.

#### 5.1.3 Mode miroir

**EX-5.6** En mode `miroir`, un adaptateur de capture (processus séparé)
reçoit la copie déchiffrée fournie par l'équipement du client (Decryption Port
Mirroring de Palo Alto Networks, licence gratuite et avis du conseil
juridique recommandé ; `decrypted-traffic-mirror` de FortiOS 8.0.0, accord
contractuel affiché à l'activation ; « Mirror and Decrypt » de Check Point
R82, R4 F1.4.1, F1.4.6, F1.4.7, C3.4), réassemble les transactions HTTP/1.1 et
les remet au démon par la prise locale, sous la forme d'un couple (requête,
réponse) horodaté, avec l'adresse source du flux. Le démon construit
l'événement comme en passerelle, avec `is_error` selon le statut HTTP
observé ; la connexion d'hôte est celle de `model.hosts` dont
`match.source_addresses` contient l'adresse source (EX-5.8). Rien n'est
bloqué, rien n'est
retenu ; une réponse tronquée dans la copie est marquée
`noortrace_flux_incomplet` (5.4). Le réassemblage HTTP/2 n'est pas couvert par
la version 0 : la documentation d'intégration le dit, et le mode miroir n'est
construit que si un client l'exige (section 21).

### 5.2 Formats de la version 0 et de la version 1

| Format | Version | Route par défaut | Raison |
|---|---|---|---|
| API Messages d'Anthropic | **v0** | `POST /v1/messages` | Référence Messages et page Streaming lues (R2 F-A2, F-A21 à F-A29) ; règle d'accumulation du SDK officiel vérifiée dans le code (`accumulate_event`, R2 F-A28) |
| Variante « Claude in Amazon Bedrock » (`bedrock-mantle.{region}.api.aws/anthropic/v1/messages`) | **v0**, route distincte | `POST /anthropic/v1/messages` | « same request body shape as Anthropic's first-party API » et « standard SSE streaming » (R2 F-A34) ; seul le libellé de fournisseur change |
| OpenAI Chat Completions | **v0** | `POST /v1/chat/completions` | Référence et page des événements de flux lues (R2 F-O2, F-O12, F-O13) ; accumulation par `index` déduite du schéma du chunk et des helpers du SDK (R2 F-O14, NV-6) ; « remains supported » (R2 F-R7) |
| OpenAI Responses | **v0** | `POST /v1/responses` | Référence et événements typés lus (R2 F-R1, F-R6) ; « recommended for all new projects » (R2 F-R7) ; l'API par défaut du SDK Agents (R7 F-61) |
| Variante Azure OpenAI « v1 » (`…/openai/v1/chat/completions`, `…/openai/v1/responses`) | **v0**, route distincte | préfixe `/openai/v1/` | Corps OpenAI, sans `api-version`, en-tête `api-key` ou `Authorization: Bearer` (R2 F-Z2) ; l'identité exacte du corps n'est vérifiée que pour la v1, pas pour l'API datée (R2 NV-10) |
| Anthropic sur Google Cloud (`rawPredict`, `streamRawPredict`) | v1 | — | `model` dans l'URL et `anthropic_version` dans le corps (R2 F-A38) ; format de sortie de `streamRawPredict` non documenté (R2 NV-5) |
| Amazon Bedrock `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` | v1 | — | Flux `application/vnd.amazon.eventstream` binaire, `chunk.bytes` en base64, corps `anthropic_version: "bedrock-2023-05-31"` ou schéma `toolUse`/`toolResult` (R2 F-A35 à F-A37, F-B1, F-B2, NV-4) |
| Gemini `generateContent`, `streamGenerateContent`, « Interactions » | v1 | — | Schéma distinct (`contents`/`parts`, `functionCall`/`functionResponse`), `alt=sse` présent seulement dans les exemples, surface « Interactions » en cours d'introduction (R2 F-G1 à F-G7, NV-8, NV-9) |
| Azure OpenAI API datée (`api-version`) | v1 | — | Chemin par déploiement, référence REST séparée non lue (R2 F-Z1, NV-10) |

**EX-5.7** Une requête reçue sur une route de la version 0 :

1. qui porte un en-tête `Content-Encoding` autre que `identity` est refusée
   par `415` ;
2. dont le corps ne s'analyse pas en **JSON strict** (clé en double,
   substitut isolé, marque d'ordre d'octets, texte qui n'est pas du JSON,
   nombre hors de la double précision, bornes de profondeur et de membres de
   4.4 pas 1) est refusée par `400` avec un corps d'erreur au format du
   fournisseur (`{"type":"error","error":{"type":"invalid_request_error","message":"noortrace: corps de requete non analysable"}}`
   pour Messages, `{"error":{"message":"noortrace: corps de requete non analysable","type":"invalid_request_error","param":null,"code":"noortrace_requete_invalide"}}`
   pour Chat Completions et Responses) ;

dans ces deux cas, rien n'est relayé, **aucun événement** n'est produit (rien
n'a atteint le fournisseur) et le refus est consigné avec la longueur, la
raison et le `Content-Type`, jamais le corps. Motif : un corps non analysable
ne peut pas être rédigé ; le stocker tel quel mettrait dans la chaîne le
clair ou son empreinte (EX-10.2), et un agent pourrait le provoquer exprès
(une clé en double suffit). 3. Une requête JSON stricte qui n'a pas la forme
attendue du format (`messages` absent pour Messages et Chat Completions ; ni
`input` ni `previous_response_id` pour Responses) est relayée telle quelle au
fournisseur — qui la refusera ou non — et donne un événement dont la pièce
« requête » est le JCS intégral du corps **rédigé** par les règles de portée
`requete` (section 8), sans pièce « prompt système » (`prompt_version:
null`) ; `code.model` est alors tiré de la réponse si elle en porte un, sinon
`null` (jamais de la requête).

### 5.3 Chemin de données

Les en-têtes suivent une **liste autorisée** : la passerelle n'envoie au
fournisseur, et ne rend à l'hôte, que les en-têtes nommés ci-dessous (plus
ceux de `model.forward_headers`, liste de noms exacts ou de préfixes terminés
par `*`, consignée au démarrage) ; tout autre en-tête est retiré et son nom
consigné.

| Classe | En-têtes | Traitement |
|---|---|---|
| Authentification de l'hôte auprès de la passerelle | `X-Noortrace-Token` ; en `credentials: "propre"`, aussi l'en-tête d'authentification du fournisseur que la route déclare (`auth_header`) | Lus pour identifier la connexion d'hôte (EX-5.8), comparés en temps constant, **toujours retirés**, jamais stockés ni journalisés |
| Délégation déclarée | `X-Noortrace-Run-Id`, `X-Noortrace-On-Behalf-Of` | Traités comme `_meta["noortrace/delegation"]` (EX-7.2), **toujours retirés** avant le relais ; tout autre `X-Noortrace-*` est retiré |
| Authentification auprès du fournisseur | `credentials: "propre"` : l'en-tête `auth_header` de la route, posé par la passerelle avec le secret de la route ; `credentials: "relayer"` : **seul** l'en-tête `auth_header` déclaré par la route est relayé tel que l'hôte l'envoie | Absents de toute pièce et de tout journal ; `Authorization`, `x-api-key`, `api-key`, `Proxy-Authorization`, `Cookie` et les en-têtes de `model.strip_headers` ne sont jamais relayés autrement |
| Relayés et notés | `anthropic-version`, `anthropic-beta`, `openai-organization`, `openai-project`, `x-client-request-id`, `user-agent`, les en-têtes d'attribution `x-claude-code-*` (R7 F-34) | Relayés vers le fournisseur inchangés ; valeur notée dans le journal d'exploitation (pas dans l'événement) |
| Relayés | `Content-Type`, `Accept` | Relayés |
| Posés par la passerelle | `Host` (celui du fournisseur amont), `Accept-Encoding: identity` (EX-5.9), `Content-Length` calculé sur les octets envoyés | Jamais recopiés de l'hôte |
| Réponse : relayés et notés | `Content-Type`, `request-id` (Anthropic, R2 F-A33), `x-request-id` et `openai-version` (OpenAI, R2 F-O3), `retry-after`, `x-should-retry`, `anthropic-ratelimit-*` (R7 F-35) | Relayés à l'hôte inchangés ; `request-id`/`x-request-id` noté dans le journal d'exploitation avec le `seq` de l'événement ; le cadrage de la réponse à l'hôte est calculé par la passerelle |

**EX-5.26** **Cadrage HTTP.** La passerelle ne relaie jamais le cadrage reçu :
une requête qui porte à la fois `Content-Length` et `Transfer-Encoding` est
refusée par `400` (la RFC 9112 §6.1 tient cette combinaison pour une
tentative possible de « request smuggling » et impose de retirer
`Content-Length` avant de transmettre, https://www.rfc-editor.org/rfc/rfc9112,
lu le 2026-10-22) ; les en-têtes nommés par `Connection` et les champs saut
par saut (`Connection`, `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`,
`Proxy-Connection`) sont retirés (RFC 9110 §7.6.1,
https://www.rfc-editor.org/rfc/rfc9110, lu le 2026-10-22) ; `Content-Length`
ou le codage `chunked` vers le fournisseur et vers l'hôte sont calculés par la
passerelle sur les octets qu'elle envoie. Une connexion amont réutilisée par
plusieurs hôtes ne peut ainsi pas servir à l'un la réponse destinée à un
autre.

**EX-5.8** La clé du fournisseur est, au choix de la configuration par route,
celle que l'hôte envoie (`credentials: "relayer"` : le seul en-tête
`auth_header` de la route traverse, l'enregistreur ne le lit que pour l'exclure
des pièces) ou celle de l'enregistreur (`credentials: "propre"` : référence de
secret ; une clé que l'hôte enverrait est retirée). Le mode `propre` est celui
qui empêche l'agent de joindre le fournisseur directement, puisqu'il n'a pas
la clé : il est recommandé avec le pare-feu de sortie.

**Connexion d'hôte de la passerelle.** Toute requête de la passerelle est
rattachée à une entrée de `model.hosts` (EX-7.3), de même forme que celles de
`mcp.hosts`, par son `match` :

1. `static_token` : le jeton statique de l'hôte est porté par l'en-tête
   `X-Noortrace-Token` ; en `credentials: "propre"`, il PEUT aussi être porté
   par l'en-tête d'authentification du fournisseur que la route déclare
   (Claude Code l'envoie par `ANTHROPIC_AUTH_TOKEN` en `Authorization: Bearer`,
   R7 F-30 à F-32), puisque l'hôte n'y a pas de clé à mettre ; en
   `credentials: "relayer"`, cet en-tête porte la clé du fournisseur et le
   jeton DOIT être dans `X-Noortrace-Token` ;
2. `oauth_subject` : jeton OAuth dont l'audience est l'URI de la passerelle,
   dans `X-Noortrace-Token` (et dans `Authorization` en mode `propre`) ;
3. `source_addresses` (liste CIDR) : modes `icap` et `miroir` seulement, où
   l'hôte ne s'authentifie pas auprès de l'enregistreur ; l'adresse est celle
   que le mandataire transmet (en-tête nommé par
   `model.icap.client_address_header`, que la configuration du mandataire
   DOIT poser ; le nom et la disponibilité de cet en-tête selon le mandataire
   ne sont pas vérifiés ici) ou celle du flux observé (miroir).

Une requête qui ne correspond à aucune entrée est refusée par `401` en
passerelle (aucun événement) ; en ICAP et en miroir, elle est rattachée à
l'entrée `model.hosts` d'`id` `"inconnu"` si la configuration en déclare une,
sinon bloquée en REQMOD (ICAP) ou consignée sans événement (miroir).
L'entrée fixe `launched_by`, `scope`, `on_behalf_of` et `host_group` comme
pour le frontal MCP (7.2). La délégation déclarée vient des en-têtes
`X-Noortrace-Run-Id` et `X-Noortrace-On-Behalf-Of`, traités exactement comme
`_meta["noortrace/delegation"]` (EX-7.2) et retirés avant le relais ; en mode
miroir ils ne peuvent pas être retirés (copie passive) et partent chez le
fournisseur. En modes `icap` et `miroir`, l'hôte ne peut en pratique ni
s'authentifier ni déclarer de `run_id` sans reconfiguration : la corrélation
par `run_id` y est impossible, seule celle par groupe d'hôte reste (5.6).

**EX-5.9** La passerelle demande au fournisseur une réponse **non comprimée**
(`Accept-Encoding: identity`) pour lire le flux ligne par ligne, et relaie à
l'hôte la réponse telle qu'elle la reçoit ; une réponse qui arrive quand même
comprimée par `gzip`, `deflate` ou `br` est décomprimée pour la pièce (dans
la borne `limits.model_response_max_bytes`, appliquée aux octets décomprimés)
et relayée comprimée à l'hôte ; un autre codage, ou une décompression qui
échoue, donne la pièce « non rédigeable » de 8.3. Les pièces portent toujours
les octets décomprimés. Une requête comprimée est refusée (EX-5.7).

#### 5.3.1 Requête et réponse hors flux

1. **Lecture de la requête.** La passerelle lit les en-têtes et le corps
   complet (limite `limits.model_request_max_bytes`, défaut 33 554 432 : la
   limite documentée de l'API Messages est 32 Mo, R2 F-A31) ; `t_recu`.
2. **Analyse.** La connexion d'hôte est établie (EX-5.8). Le corps est
   analysé en JSON strict (EX-5.7) ; le format de la route s'applique (5.5 :
   modèle demandé, prompt système, `stream`).
3. **Pièces de requête.** Le rédacteur applique les règles de portée `requete`
   et `prompt_systeme` ; le noyau produit la pièce « prompt système » (8.2) et
   la pièce « requête » (JCS intégral du corps rédigé, où le prompt système est
   remplacé par la chaîne `[REDIGE:prompt-systeme]` si la configuration
   `model.prompt_in_request: "reference"` est active, défaut ; avec
   `"inline"`, chaque chaîne porteuse du prompt reste en place, rédigée par
   les règles de portée `prompt_systeme` avant les règles de portée
   `requete`, EX-8.5), les écrit et `fsync`.
4. **Envoi.** La requête est envoyée au fournisseur : en-têtes selon la table
   ci-dessus, corps = **octets reçus recopiés** ; `t_envoi`. Délai de
   connexion `model.connect_timeout_ms` (défaut 10 000).
5. **Réponse.** Les en-têtes de réponse arrivent ; le **type de média** du
   `Content-Type` (en minuscules, sans paramètres) décide :
   `application/json` ou un type de suffixe `+json` → corps lu entièrement
   (limite `limits.model_response_max_bytes`, défaut 33 554 432) et analysé
   en JSON strict ; `text/event-stream` → 5.3.2 ; tout autre type, ou un
   corps qui ne s'analyse pas → corps lu, pièce non JSON (8.3). Un corps
   JSON reçu sous un autre type n'est pas analysé : `code.model` et `intent`
   ne sont tirés que d'un corps JSON déclaré comme tel. `t_reponse` à la fin
   du corps ; `duration_ms = t_reponse − t_envoi`.
6. **Relais.** Le corps est relayé à l'hôte octet pour octet, avec le statut et
   les en-têtes de la table (en hors flux, le relais peut commencer avant la
   fin de la lecture : la passerelle ne tamponne pas plus qu'elle ne doit pour
   hacher).
7. **Pièce « réponse ».** Statut `2xx` et corps JSON : le rédacteur applique les
   règles de portée `reponse`, le noyau sérialise en JCS intégral, `is_error:
   false` ; statut `2xx` et corps non JSON : pièce non JSON (8.3), `is_error:
   true`. Statut `≥ 400` : la pièce est l'objet `{"noortrace_http_error":
   {"status": <entier>, "content_type": <valeur reçue ou null>, "body": <corps
   JSON analysé si le type de média est JSON et que le corps s'analyse, sinon
   chaîne UTF-8 si le corps est de l'UTF-8 valide, sinon l'objet
   `noortrace_non_redigeable` d'EX-8.7, ou null si vide>}}`
   en JCS intégral, rédigé par les règles de portée `reponse` (les chaînes du
   corps sont donc examinées), `is_error: true` ; la forme de corps d'erreur
   d'Anthropic (`{"type":"error","error":{"type","message"},"request_id"}`,
   R2 F-A32) y figure donc en entier, celle d'OpenAI telle que reçue (non
   recherchée, R2 NV-11).
8. **Événement.** Dès que la forme de la réponse est complète en mémoire (corps
   lu, ou forme consolidée close), elle est inscrite, rédigée, au **registre
   de corrélation** de 5.6, avant le scellement ; puis
   `noortrace.modele.echange` (section 7.2) est scellé, ajouté, `fsync`.
   **Un échange de modèle ne retient jamais la réponse à l'hôte** :
   l'hôte a déjà tout reçu au pas 6 ; la durabilité de l'événement est
   assurée avant que la passerelle accepte la requête suivante de la même
   connexion d'hôte, et un échec d'écriture fait entrer en mode dégradé
   (section 14) sans annuler ce qui a été relayé.

**EX-5.10** L'ordre des pas 3, 4, 6, 7 et 8 DOIT être respecté : la pièce
« requête » est durable avant l'envoi au fournisseur ; la réponse n'est pas
retenue en attendant l'événement.

#### 5.3.2 Réponse en flux (SSE)

**EX-5.11** Quand la réponse amont est `text/event-stream`, la passerelle :
(a) relaie à l'hôte les en-têtes de réponse dès réception avec `Content-Type:
text/event-stream` ; (b) relaie **chaque octet** reçu du fournisseur dès
réception, sans attendre une fin d'événement, sans tampon autre que celui de
la lecture réseau ; (c) en parallèle, analyse le flux avec l'analyseur de
5.4.1 pour construire la forme consolidée ; (d) à la fin du flux (fermeture
amont), clôt le flux vers l'hôte, `t_reponse`, puis exécute les pas 7 et 8
de 5.3.1 avec la forme consolidée comme corps (l'inscription au registre de
corrélation a lieu dès l'analyse de l'événement terminal, avant le
scellement). La latence ajoutée au premier
octet et la mesure de l'absence de tampon sont les objectifs de la section 16.

**EX-5.12** Les commentaires SSE (lignes commençant par `:`) et les événements
`ping` d'Anthropic (R2 F-A22) sont relayés comme tout autre octet (Claude Code
en a besoin pendant les pauses, R7 F-35) et ignorés par l'analyseur.

**EX-5.13** Un flux coupé par le fournisseur avant son événement terminal
(`message_stop`, `data: [DONE]`, `response.completed`/`failed`/`incomplete`)
donne une forme consolidée marquée `"noortrace_flux_incomplet": true` et
`is_error: true` ; la coupure côté hôte (l'hôte ferme) fait fermer la
connexion amont et donne la même marque. La passerelle NE DOIT PAS réémettre
la requête (5.7).

### 5.4 Réassemblage des flux, fournisseur par fournisseur

#### 5.4.1 Analyseur SSE commun

**EX-5.14** L'analyseur suit la section « Parsing an event stream » du HTML
Living Standard (R2 F-E1 à F-E5) : décodage UTF-8 avec retrait d'une marque
d'ordre d'octets initiale ; fins de ligne CRLF, LF ou CR ; une ligne vide
distribue l'événement ; une ligne commençant par `:` est ignorée ; une ligne
avec `:` donne le champ avant le premier `:` et la valeur après, privée d'un
seul espace initial ; une ligne sans `:` est un nom de champ à valeur vide ;
`event` fixe le type ; chaque `data` est ajouté au tampon suivi de `\n`, le
dernier `\n` est retiré à la distribution ; `id` et `retry` sont lus et
ignorés par l'enregistreur ; tout autre champ est ignoré ; le type par défaut
est `message` ; un tampon `data` vide ne distribue rien ; un `data` en attente
sans ligne vide finale n'est pas distribué. La valeur `data` distribuée est
analysée en JSON ; une valeur qui n'est pas du JSON (`[DONE]` chez OpenAI) est
traitée par la règle du fournisseur.

**EX-5.27** Règles communes aux trois réassemblages, qui bornent ce qu'un
fournisseur (ou un flux altéré) peut faire de la forme consolidée : (1) un
**index** (`index` d'Anthropic et de Chat Completions, `output_index` de
Responses) n'est admis que s'il est un nombre JSON de valeur entière, au
moins 0 et au plus 2^53 (une chaîne `"0"` n'est pas un index) ; (2) un
index qui désigne une position d'un tableau (`content` d'Anthropic, `output`
de Responses) n'est admis que s'il est au plus égal à la longueur courante du
tableau (égal : l'élément est ajouté ; inférieur : il est remplacé) ; un index
plus grand est ignoré, ce qui interdit les trous et l'amplification d'un
flux court en une pièce énorme ; (3) un événement, un choix ou un fragment
dont un membre attendu manque ou n'a pas le type attendu (objet pour
`content_block`, `citation`, `delta`, un choix, un fragment d'appel, `item` ;
chaîne pour `text`, `partial_json`, `thinking`, `signature`) est ignoré ;
(4) tout événement ignoré est compté dans le journal d'exploitation et
n'est jamais une erreur de l'enregistreur (EX-7.1).

#### 5.4.2 API Messages d'Anthropic

Les événements sont nommés (`event:` puis `data:` portant `type`) et suivent
`message_start`, puis des blocs (`content_block_start`, `content_block_delta`,
`content_block_stop`), puis `message_delta` et `message_stop`, avec des `ping`
possibles et un `error` possible (page Streaming, R2 F-A21 à F-A27). La règle
d'accumulation est celle de la page Streaming et du SDK officiel
(`accumulate_event`, R2 F-A26, F-A28).

**EX-5.15** Forme consolidée Anthropic :

1. `message_start` : la forme consolidée est l'objet `message` reçu (avec
   `content: []`, `stop_reason: null`, `usage`) ; un second `message_start`,
   ou un `message` qui n'est pas un objet, est ignoré. Tout événement dont la
   donnée est un objet JSON, d'un type autre que `message_start`, `ping` ou
   `error`, reçu avant `message_start`, est ignoré et rend le flux incomplet
   (`noortrace_flux_incomplet`), quel que soit son type, connu ou non.
2. `content_block_start` : `content_block` (un objet) est placé à la position
   `index` (EX-5.27 ; si `content` n'est pas un tableau, il le devient). Pour
   un bloc `tool_use`, un tampon de texte vide lui est associé.
3. `content_block_delta` à `index` (le bloc à cette position doit être un
   objet) : `text_delta` → `content[index].text += delta.text` ;
   `input_json_delta` → tampon du bloc `+= delta.partial_json`, le tampon
   étant créé vide au premier `input_json_delta` d'un bloc qui n'en a pas
   (`server_tool_use` et tout autre type ; le SDK officiel tient un tampon par
   bloc, R2 F-A28 ; le premier delta peut être `""`, R2 F-A27) ;
   `thinking_delta` → `content[index].thinking += delta.thinking` ;
   `signature_delta` → `content[index].signature = delta.signature` ;
   `citations_delta` → ajout de `delta.citation` à `content[index].citations`
   (tableau créé au besoin) ; un type de delta inconnu, ou un membre absent ou
   mal typé (EX-5.27), est ignoré et compté.
4. `content_block_stop` à `index` : pour un bloc qui a un tampon, si le
   tampon est vide, `input = {}` ; sinon le tampon est analysé en JSON strict
   et devient `input` ; si l'analyse échoue, `input = {}` et le bloc reçoit
   `"noortrace_input_json_invalide": <tampon>` (chaîne).
5. `message_delta` : chaque membre présent de `delta` (`stop_reason`,
   `stop_sequence`, `stop_details`) remplace celui de la forme ; chaque membre
   présent de `usage` remplace celui de la forme (totaux cumulatifs, « they
   overwrite rather than add », R2 F-A28) ; un membre absent conserve la
   valeur de `message_start`.
6. `message_stop` : fin normale.
7. `error` : la forme reçoit `"noortrace_erreur_flux": <objet data de
   l'événement>` et `is_error = true` ; reçu avant `message_start`, il donne
   la forme réduite `{"noortrace_erreur_flux": <objet data>}` ; ce qui suit
   éventuellement n'est pas documenté (R2 NV-13) et est ignoré.
8. `ping`, commentaires et types inconnus (« your code should handle unknown
   event types gracefully », R2 F-A24) : ignorés, comptés dans le journal
   d'exploitation.

Les sept valeurs de `stop_reason` (`end_turn`, `max_tokens`, `stop_sequence`,
`tool_use`, `pause_turn`, `refusal`, `model_context_window_exceeded`, R2
F-A19) sont acceptées telles quelles ; l'enregistreur n'en déduit rien.

#### 5.4.3 OpenAI Chat Completions

Les événements sont `data:` seuls, sans ligne `event:`, chaque `data` porte un
objet `chat.completion.chunk` de même `id`, et le flux se termine par `data:
[DONE]` (R2 F-O7, F-O12, F-O13). L'accumulation par `index` est déduite du
schéma du chunk et des helpers du SDK Python, aucune phrase officielle en prose
ne la décrit pour Chat Completions (R2 F-O14, NV-6) : la règle est fixée ici.

**EX-5.16** Forme consolidée Chat Completions :

1. Au premier chunk : `id`, `created`, `model`, `system_fingerprint`,
   `service_tier` recopiés s'ils sont présents ; `object = "chat.completion"` ;
   `choices = []` ; `usage` absent.
2. Pour chaque `choices[i]` d'un chunk (un objet dont `index` est admis par
   EX-5.27), le choix d'`index` égal est créé au besoin, à la suite des
   autres, avec `{"index": n, "message": {"role": "assistant", "content":
   null}, "finish_reason": null}` ; puis : `delta.role` (chaîne) →
   `message.role` ; `delta.content` (chaîne) → `message.content` =
   `message.content` (ou `""` si `null`) `+ delta.content` ; `delta.refusal`
   (chaîne) → même règle sur `message.refusal` ; chaque fragment
   `delta.tool_calls[j]` (un objet dont `index` est admis) → l'appel d'outil
   d'`index` égal dans `message.tool_calls` (tableau créé au besoin) est créé
   au besoin, à la suite, avec `{"index": n, "id": null, "type": "function",
   "function": {"name": "", "arguments": ""}}`, puis `id`, `type` et
   `function.name` sont fixés par le premier fragment qui les porte avec une
   valeur **non nulle** (un `null` ne fixe rien), et `function.arguments +=
   fragment.function.arguments` (chaîne) ; `finish_reason` non `null` →
   `finish_reason` du choix.
3. Un chunk dont `usage` n'est pas `null` fournit `usage` (seulement avec
   `stream_options.include_usage`, « except for the last chunk », R2 F-O12).
4. Le champ `obfuscation` n'est jamais recopié (R2 F-O12) ; `logprobs` n'est
   pas consolidé en version 0 (noté).
5. `data: [DONE]` : fin normale. Un chunk dont l'`id` diffère de celui du
   premier chunk (comparaison des JCS intégraux, un `id` absent valant
   `null`) **arrête** le réassemblage : ce chunk et tout ce qui suit, `[DONE]`
   compris, sont ignorés, et le flux est incomplet.

`function.arguments` est « as generated by the model in JSON format. Note that
the model does not always generate valid JSON » (R2 F-O10) : la chaîne est
conservée telle quelle, jamais analysée pour la pièce.

#### 5.4.4 OpenAI Responses

Les événements sont `data:` seuls, chaque `data` porte un objet dont `type`
nomme l'événement ; les objets `Response` complets sont portés par
`response.created`, `response.in_progress`, `response.completed`,
`response.failed`, `response.incomplete` (R2 F-R5, F-R6, F-R9).

**EX-5.17** Forme consolidée Responses : l'objet `response` du **dernier**
événement reçu parmi `response.created`, `response.in_progress`,
`response.completed`, `response.failed`, `response.incomplete` (un événement
de ces types dont `response` n'est pas un objet est ignoré). Si ce dernier
événement est `response.completed`, `response.failed` ou
`response.incomplete`, la fin est normale (`is_error` vaut `true` pour
`failed`). Sinon le flux est incomplet : la forme reçoit
`"noortrace_flux_incomplet": true` et, dans `output` (créé vide s'il n'est
pas un tableau), les items `response.output_item.done` reçus sont placés
dans l'ordre croissant d'`output_index` (pour un même index, le dernier reçu),
chacun selon EX-5.27 (2) : il remplace l'item de même position, ou s'ajoute
s'il désigne la position qui suit le dernier ; un index plus grand est
ignoré. Un événement `error` donne `"noortrace_erreur_flux": {"code": …,
"message": …}` (`null` pour un membre absent) et `is_error: true`. Si
**aucun** objet `response` n'a été reçu : avec un `error`, la forme est
réduite à `{"noortrace_erreur_flux": {"code": …, "message": …}}` ; sans
`error`, il n'y a pas de forme consolidée, et la pièce « réponse » est le
flux brut (EX-8.7). Les deltas (`response.output_text.delta`,
`response.function_call_arguments.delta`) ne sont pas accumulés : la réponse
terminale les contient.

**EX-5.18** Les trois formes consolidées sont des valeurs JSON ; la pièce
« réponse » est leur JCS intégral après rédaction (section 8). Les clés
`noortrace_flux_incomplet`, `noortrace_erreur_flux` et
`noortrace_input_json_invalide` sont les seules que l'enregistreur ajoute à
une forme consolidée ; un vérificateur ou un lecteur les reconnaît à leur
préfixe.

### 5.5 Extraction

| Grandeur CT-1 | Anthropic Messages | OpenAI Chat Completions | OpenAI Responses | Si absent |
|---|---|---|---|---|
| `code.model` | `<libellé de la route>/` + `message.model` de la réponse (hors flux) ou de la forme consolidée | `<libellé>/` + `completion.model` | `<libellé>/` + `response.model` | `<libellé>/` + `model` de la requête si elle a la forme attendue (EX-5.7) ; sinon `null` |
| Prompt système (pièce) | `system` : chaîne, ou concaténation des `text` des blocs `TextBlockParam` (type `text`) séparés par `\n` (R2 F-A9) | Concaténation, dans l'ordre, des `content` des messages de rôle `system` et `developer` (chaîne, ou `text` de leurs parties de type `text`), séparés par `\n` (R2 F-O4) | `instructions` (chaîne), puis les `content` des items de rôle `developer` ou `system` de `input` (chaîne, ou `text` de leurs parties de type `input_text` ou `text`), séparés par `\n` (R2 F-R1) | pas de pièce, `prompt_version: null` |
| `code.prompt_version` | SHA-256 des octets UTF-8 de la pièce « prompt système » rédigée (8.2) | idem | idem | `null` |
| `intent` | Concaténation des `text` des blocs `content` de type `text` de la réponse, séparés par `\n` | `choices[0].message.content` | Concaténation des `text` des parties `output_text` des items `message` de `output`, séparés par `\n` | `null` |
| Appels d'outils demandés par le modèle (pour 5.6) | blocs `tool_use` : `id`, `name`, `input` (R2 F-A15) | `choices[0].message.tool_calls[]` : `id`, `function.name`, `function.arguments` (chaîne JSON) (R2 F-O10) | items `function_call` : `call_id`, `name`, `arguments` (chaîne JSON) (R2 F-R3) | aucun |
| Résultats d'outils fournis par l'hôte | blocs `tool_result` : `tool_use_id`, `content`, `is_error` (R2 F-A16) | messages `role: "tool"` : `tool_call_id`, `content` (R2 F-O8) | items `function_call_output` : `call_id`, `output` (R2 F-R4) | aucun |
| Usage | `usage` (`input_tokens`, `output_tokens`, caches ; cumulatif en flux, R2 F-A20, F-A21) | `usage` (dernier chunk seulement, R2 F-O12) | `usage` (R2 F-R2) | — |

**EX-5.19** Le libellé de fournisseur est celui de la route de configuration
(`provider_label`, motif `^[a-z0-9][a-z0-9.-]{0,31}$` ; valeurs recommandées :
`anthropic`, `openai`, `bedrock-mantle`, `azure-openai`) ; `code.model` =
`<libellé>/<champ model de la réponse>`, tronqué à 256 caractères si
nécessaire (borne de CT-1). Le modèle de la réponse prime sur celui de la
requête parce que c'est celui qui a servi.

**EX-5.20** `usage` n'entre pas dans l'événement (CT-1 n'a pas de champ pour
lui) : il est dans la pièce « réponse » et dans le journal d'exploitation et
les métriques (section 17).

**EX-5.21** `intent` est le texte produit par l'assistant, extrait (table
ci-dessus) de la **réponse déjà rédigée** par les règles de portée `reponse`
(la valeur de la pièce « réponse », EX-10.18), jamais de la réponse en clair ;
s'il dépasse 4096 caractères, ou s'il diffère du texte que l'extraction
donnerait sur la réponse en clair (une règle de rédaction l'a modifié), il
devient une référence à une pièce (CT-1 §5.3 : « ou référence quand le texte
est plus long ou rédigé ») dont les octets sont le texte UTF-8, `media_type:
"text/plain"`, et `redacted` vaut `true` dans le second cas.

### 5.6 Corrélation appel d'outil ↔ échange de modèle

Pour un appel d'outil, CT-1 veut comme `intent` « le texte de l'assistant qui
précède l'appel dans la réponse du modèle, s'il existe », et comme
`code.model` et `code.prompt_version` ceux de l'échange qui a produit l'appel.
Le frontal MCP ne voit pas la réponse du modèle ; le frontal modèle la voit.
La règle de corrélation est déclarée ici et ses limites aussi.

**Registre de corrélation.** Le frontal modèle inscrit chaque échange au
registre de corrélation dès que la forme de sa réponse est complète en
mémoire (5.3.1 pas 8, EX-5.11 (d)), **avant** son scellement, avec : la
connexion d'hôte et son groupe, le `run_id` déclaré ou `null`, l'instant
`t_complet` d'inscription, la réponse en clair (pour la seule comparaison des
appels d'outils ; elle ne quitte pas la mémoire et disparaît à la sortie de
la fenêtre) et, dès qu'elle est calculée, la réponse rédigée (valeur de la
pièce « réponse »), dont viennent `intent`, `code.model` et
`code.prompt_version`. La passerelle analyse chaque fragment lu du
fournisseur avant de l'écrire vers l'hôte (sans autre tampon que celui de la
lecture réseau, EX-5.11) : la forme en clair est close et inscrite avant que
l'hôte reçoive les derniers octets de la réponse, de sorte qu'un hôte qui a
reçu toute la réponse trouve l'échange inscrit, même si son scellement
(signature réseau, `fdatasync` groupé) n'est pas fini. La **décision** de
correspondance ne dépend que de la forme en clair ; si la réponse rédigée
d'un échange retenu n'est pas encore calculée, le pas 3 de 4.4 attend qu'elle
le soit (calcul local, borné par `limits.redaction_budget_ms`, EX-10.23) :
l'attente change la latence, jamais le résultat.

**EX-5.22** Règle. Pour un `tools/call` de nom annoncé `N`, d'arguments en
clair `A` (valeur JSON), reçu à `t_recu` sur une connexion d'hôte de groupe
`G` (`host_group` de son entrée de configuration) et de `run_id` déclaré `R`
(ou `null`), l'enregistreur cherche, parmi les échanges du registre de
corrélation dont la connexion d'hôte a le **même groupe `G`**, qui, si `R` et
leur propre `run_id` sont tous deux non nuls, ont le **même `run_id`**,
inscrits dans la fenêtre `[t_recu − model.correlation_window_ms, t_recu]`
(défaut 600 000) et non encore consommés, le **plus récent** dont la forme
consolidée contient un appel d'outil demandé par le modèle (table de 5.5) tel
que :

1. le nom vu par le modèle correspond à `N` : égalité, ou égalité après
   application du gabarit `tool_name_template` et, s'il est actif, de la
   normalisation `tool_name_sanitize` de la connexion d'hôte (section 15 ;
   par exemple `mcp__noortrace__{tool_announced}` avec `tool_name_sanitize:
   true` pour Claude Code, où `.` et les caractères hors `A-Z a-z 0-9 _ -`
   du nom deviennent `_`, R9 F-05 ; le gabarit par défaut est
   `{tool_announced}` sans normalisation, c'est-à-dire l'identité) ;
2. les arguments correspondent : `JCS_integral(A) = JCS_integral(args)`, où
   `args` est `input` (Anthropic) ou le résultat de l'analyse JSON de la
   chaîne `arguments` (OpenAI) ; une chaîne `arguments` qui n'est pas du JSON
   ne correspond jamais.

Si un échange correspond : `intent` = le texte de l'assistant qui précède
l'appel, extrait de la **réponse rédigée** (Anthropic : concaténation des
blocs `text` d'index inférieur à celui du bloc `tool_use` ; Chat Completions
: `choices[0].message.content` ; Responses : concaténation des `output_text`
des items `message` d'`output_index` inférieur), borné et mis en référence
comme en EX-5.21 ; `code.model` et `code.prompt_version` = ceux de
l'échange ; l'appel du modèle est marqué consommé (un même bloc `tool_use` ne
sert qu'à un appel). Sinon : `intent`, `code.model` et `code.prompt_version`
valent `null` ; aucun échange antérieur n'est repris par défaut. Le
résultat de la corrélation (`seq` de l'échange, ou de son inscription s'il
n'est pas encore scellé, ou `aucun`) est consigné dans le journal
d'exploitation. Une ré-émission après approbation ne passe pas par cette
règle : elle reprend l'intention de l'appel retenu (4.4 pas 3, EX-7.12).

Limites, dites en clair : la corrélation est heuristique et **déclarative** ;
elle échoue si l'hôte réécrit les arguments entre le modèle et l'appel MCP, si
le modèle demande deux appels identiques, si plusieurs agents partagent un
groupe d'hôte sans déclarer de `run_id`, si l'hôte exécute un appel d'outil
avant la fin de la réponse du modèle (au `content_block_stop` du bloc
`tool_use`, par exemple : l'échange n'est alors pas encore inscrit), ou si le
frontal modèle est désactivé. En modes `icap` et `miroir`, l'hôte ne déclare
pas de `run_id` (EX-5.8) : seule la règle de groupe s'applique. Le groupe
d'hôte est fixé par le client, jamais par l'hôte : une session SDK ou un hôte
d'un autre groupe ne peut pas faire attribuer son échange aux appels d'un
agent en déclarant son `run_id`. Un `intent` corrélé n'est pas une preuve
que ce texte a causé cet appel : il est le texte que le modèle a produit
avant de demander un appel identique.

### 5.7 Erreurs HTTP, délais, aucune relance autonome

**EX-5.23** Une réponse de statut `≥ 400` est relayée à l'hôte avec son statut,
ses en-têtes et son corps inchangés (Claude Code fonde ses relances sur le
libellé des erreurs amont : « forward error response bodies unmodified », R7
F-36) et donne un événement `is_error: true` dont la pièce « réponse » est
l'objet `noortrace_http_error` de 5.3.1. Les codes documentés par Anthropic
(`400 invalid_request_error`, `401`, `402`, `403`, `404`, `409`, `413
request_too_large`, `429 rate_limit_error`, `500 api_error`, `504
timeout_error`, `529 overloaded_error`, R2 F-A31) et une erreur en cours de
flux après un `200` (R2 F-A23) sont tous des échanges `executee` avec
`is_error: true`, comme CT-1 §5.3 l'exige (« une requête qui n'obtient pas de
réponse exploitable est journalisée avec `is_error: true` »).

**EX-5.24** Délais : `connect_timeout_ms` (connexion au fournisseur, défaut
10 000), `first_byte_timeout_ms` (premier octet de réponse, défaut 120 000),
`idle_timeout_ms` (silence entre deux octets d'un flux, défaut 120 000). Au
délai, la passerelle ferme la connexion amont et répond à l'hôte `504` avec le
corps `{"type":"error","error":{"type":"noortrace_timeout","message":"noortrace:
delai du fournisseur depasse"}}` (si rien n'a encore été relayé) ou clôt le
flux (si la réponse est déjà en cours) ; l'événement porte `is_error: true`
et la pièce `{"noortrace_http_error": {"status": 504, "content_type": null,
"body": {"noortrace_timeout": {"phase": "connexion" ou "premier_octet" ou
"inactivite", "timeout_ms": N}}}}` ou la forme consolidée incomplète.

**EX-5.25** La passerelle NE DOIT jamais réémettre d'elle-même une requête de
modèle (pas de relance sur `429`, `500`, `529`, ni sur coupure) : la relance
appartient au SDK de l'hôte, et chaque tentative est un échange distinct dans
la chaîne. Elle relaie `retry-after` et `x-should-retry` tels quels (R7 F-35).

### 5.8 Ce qui n'est pas capturé

- Les couples (méthode, chemin) de la liste `passthrough` d'une route
  (`/v1/messages/count_tokens`, `/v1/models`) : relayés sans événement,
  consignés ; tout autre chemin (lots, fichiers, plongements, modération) est
  refusé par `404` (EX-5.2).
- Les transports non HTTP (WebSocket du SDK Agents, `OPENAI_WEBSOCKET_BASE_URL`,
  R7 F-67 ; API temps réel) : non pris en charge en version 0.
- Les formats de la version 1 (5.2).
- Ce que le fournisseur fait du côté serveur (outils serveur, recherche web,
  `store: true` par défaut chez Responses qui conserve la réponse 30 jours au
  moins, R2 F-R1, F-R8) : l'enregistreur voit la requête et la réponse, pas
  ce qui est advenu chez le fournisseur ; une requête Responses avec
  `previous_response_id` ne contient pas tout le contexte (R2 F-R8), et la
  pièce « requête » non plus.
- Le contenu exact d'un flux dont l'hôte a fermé la connexion : la forme est
  incomplète, marquée comme telle.
- Les en-têtes de la réponse (`request-id`) : dans le journal d'exploitation,
  pas dans la chaîne (limite de la version 0 ; à reconsidérer en version 1 si
  un réviseur demande que l'identifiant du fournisseur soit prouvable).
- L'exécution des outils par l'hôte lui-même quand le frontal MCP n'est pas
  sur le chemin : visible seulement par les `tool_result` de la requête
  suivante, qui sont dans la pièce « requête ».

## 6. SDK

### 6.1 Périmètre

Le SDK couvre le cas restant de l'architecture : un agent qui exécute lui-même
des outils sans MCP (fonctions locales, bibliothèques), ou qui parle à un
modèle que la passerelle ne voit pas (modèle local, format de la version 1).
Le SDK **ne capture rien par lui-même** : il remet au démon, par la prise
locale, ce que l'agent déclare, et le démon fait le reste (politique,
rédaction, pièces, scellement, stockage). Il ne détient ni clé, ni politique,
ni stockage.

**EX-6.1** Le SDK est une bibliothèque dans le processus de l'agent qui parle
au démon par une prise de domaine Unix (ou une prise TCP locale) avec le
cadrage de 4.7.1 (une ligne JSON-RPC 2.0 par message) ; le démon l'authentifie
par l'identité du processus pair (prise Unix) ou par un jeton statique ou mTLS
(TCP, obligatoire, EX-4.39), et lui associe l'entrée de `sdk.hosts` qui
correspond, donc une délégation et un groupe d'hôte de la configuration
(section 7.2). Le SDK NE
DOIT PAS contenir de code de hachage, de signature ou d'écriture de journal :
le journal n'est jamais écrit depuis le processus de l'agent.

**EX-6.2** Le SDK n'est acceptable comme chemin de capture qu'avec un pare-feu
de sortie qui interdit au processus de l'agent de joindre les serveurs
d'outils et les fournisseurs de modèle autrement que par l'enregistreur (4.9,
5.1). La documentation (section 19) le dit en tête : un agent qui peut
atteindre ses cibles directement peut n'appeler le SDK que pour ce qu'il veut
montrer.

### 6.2 Interface minimale

Toutes les fonctions sont des méthodes JSON-RPC du démon, préfixées
`noortrace/sdk/` ; les SDK de langage les enveloppent sans en changer la
sémantique. Les valeurs sont celles de CT-1.

| Méthode | Paramètres | Résultat | Effet |
|---|---|---|---|
| `noortrace/sdk/ouvrir` | `{ "run_id": chaîne ou null, "on_behalf_of": chaîne ou null }` | `{ "session": chaîne, "org_id", "journal_id", "policy_version" }` | Ouvre une session SDK ; `launched_by` et `scope` viennent de la configuration de la connexion d'hôte (EX-7.3), `run_id` et `on_behalf_of` sont déclarés par l'agent (déclaratif) |
| `noortrace/sdk/declarerContexte` | `{ "session", "kind": "document" ou "donnees" ou "memoire" ou "autre", "media_type": chaîne ou null, "bytes_base64": chaîne }` | `{ "sha256", "length", "redacted" }` | Le démon rédige si la politique le prévoit (portée `contexte`), stocke la pièce, rend la référence ; l'agent la cite ensuite par `sha256`, dans la même session seulement |
| `noortrace/sdk/debutAppel` | `{ "session", "tool": nom court (motif CT-1, sans `__`, hors `noortrace.`), "arguments": valeur JSON, "class": "lecture" ou "ecriture" ou null, "context": [sha256…], "intent": chaîne ou null, "effects": [effets déclarés] ou null }` | `{ "call": chaîne ou null, "decision": "autorise" ou "a_approuver" ou "refuse", "ticket": chaîne ou null, "ticket_state": "nouveau" ou "en_attente" ou "approuve" ou "refuse" ou "expire" ou null }` | Pas 2 à 8 de 4.4 : nom annoncé `<alias SDK>__<tool>` (EX-6.6), classe (déclarée, à défaut configuration, à défaut `ecriture`), politique (réponse d'`evaluer`, EX-7.16), pièce « arguments », événement `retenue` ou `refusee` s'il y a lieu, vérifications de relais pour un ticket approuvé (EX-7.21), intention écrite et `fsync` pour `ecriture` ; le SDK n'exécute l'outil que si `decision = "autorise"` (EX-6.7) ; `call` est nul sauf pour `autorise` |
| `noortrace/sdk/finAppel` | `{ "call", "result": valeur JSON ou null, "is_error": booléen, "duration_ms": entier }` | `{ "seq", "hash" }` | Pas 12 et 13 : pièce « résultat », événement `executee` scellé et durable ; le résultat est rendu après `fsync` |
| `noortrace/sdk/echangeModele` | `{ "session", "format": "anthropic-messages" ou "openai-chat" ou "openai-responses" ou "autre", "provider_label", "request": valeur JSON, "response": valeur JSON, "status": entier HTTP ou null, "duration_ms": entier, "is_error": booléen }` | `{ "seq", "hash" }` | Événement `noortrace.modele.echange` ; pour un format v0, l'extraction de 5.5 s'applique ; pour `autre`, `code.model = provider_label + "/" + request.model` si présent, `intent = null`, `prompt_version = null` |
| `noortrace/sdk/fermer` | `{ "session" }` | `{}` | Clôt la session ; un `debutAppel` sans `finAppel` à la fermeture donne l'événement de reprise de la section 12 (l'agent a disparu pendant l'appel) |

**EX-6.3** `debutAppel` DOIT précéder l'exécution de l'outil par l'agent et
`finAppel` la suivre ; la durée `duration_ms` est mesurée par le SDK autour de
l'exécution. Un `debutAppel` pour un outil de classe `ecriture` n'est rendu
qu'après le `fsync` de l'intention (EX-4.19 appliqué au SDK). Un `finAppel`
sans `debutAppel` connu est refusé (`-32602`).

**EX-6.4** Les erreurs rendues au SDK sont les codes de la table de 4.4
(`-31010` en mode dégradé pour une écriture ou pour un service
d'approbation indisponible ou en défaut) et les codes JSON-RPC standard,
dans les limites d'EX-4.24. L'issue d'une politique d'approbation n'est pas
une erreur : elle est dans le résultat de `debutAppel` (`decision`,
`ticket`, `ticket_state`, EX-6.7).

**EX-6.6** **Espace de noms et validation des entrées du SDK.** Chaque entrée
de `sdk.hosts` porte un `alias` (motif d'EX-4.9, distinct de tout alias de
serveur d'outils et réservé au SDK) ; le nom d'outil d'un événement déclaré
par le SDK est `<alias>__<tool>`, de sorte qu'aucun événement du SDK ne peut
porter le nom d'un outil annoncé par le frontal MCP ni lui ressembler ; un
`tool` qui contient `__` ou commence par `noortrace.` est refusé. Le démon
valide **à l'entrée**, et refuse par `-32602` (`data.reason`) sans pièce,
sans événement et sans mode dégradé : un `tool` hors motif ; une valeur de
`context` hors `^0x[0-9a-f]{64}$`, ou qui ne désigne pas une pièce déclarée
par `declarerContexte` **dans la même session** ; un `intent` de plus de
1 048 576 caractères ; un effet déclaré qui ne respecte pas la forme de CT-1
§5.3. Les chaînes `system` et `object` des effets déclarés sont soumises aux
détecteurs de texte des règles de portée `arguments` applicables à l'outil
`<alias>__<tool>` (sélecteur `tools`), avec leur action, avant d'entrer dans
l'événement (EX-7.6) ; leur `path` n'est pas résolu : la chaîne est la
racine. Une donnée d'entrée invalide n'atteint ainsi jamais la construction
de l'événement (EX-7.1).

**EX-6.7** **Approbation par le SDK.** `debutAppel` applique la réponse
d'`evaluer` comme le frontal MCP (EX-7.16), sans jamais retenir de requête
(l'agent n'attend pas sur une connexion ouverte) ; il rend :

| Réponse d'`evaluer` | Effet côté démon | Résultat de `debutAppel` |
|---|---|---|
| `autorise`, sans ticket | intention pour `ecriture` (EX-6.3) | `{ "call", "decision": "autorise", "ticket": null, "ticket_state": null }` |
| `refuse`, sans ticket | événement `refusee` | `{ "call": null, "decision": "refuse", "ticket": null, "ticket_state": null }` |
| `a_approuver`, `nouveau` | EX-7.17, événement `retenue`, fichiers des approbations, `ouvrir` | `{ "call": null, "decision": "a_approuver", "ticket", "ticket_state": "nouveau" }` |
| `a_approuver`, `en_attente` | aucun événement, `approval_pending` consigné | `{ "call": null, "decision": "a_approuver", "ticket", "ticket_state": "en_attente" }` |
| `autorise`, `approuve` | RL-1 à RL-4 (EX-7.21 ; RL-2 compare le nom `<alias SDK>__<tool>`, la délégation de la session et le MAC des arguments déclarés), puis intention | `{ "call", "decision": "autorise", "ticket", "ticket_state": "approuve" }` |
| `refuse`, `refuse` ou `expire` | événement `refusee` qui reprend la `policy` de la `retenue` et porte l'`approval` scellé (EX-7.12) | `{ "call": null, "decision": "refuse", "ticket", "ticket_state" }` |

Le SDK n'exécute l'outil que pour `decision: "autorise"` ; l'événement
`executee` de `finAppel` porte alors l'approbation (EX-7.12), et le noyau
envoie `consommer` après lui (EX-7.20). Un `debutAppel` approuvé sans
`finAppel` donne l'événement de reprise de 12.5, qui porte aussi
l'approbation et la consomme. Une réponse qui n'est pas applicable (EX-7.16)
rend `-31010`, raison `approbation` ; une pièce « arguments » au-delà de la
borne de temps, pour un outil de classe `ecriture` ou susceptible
d'approbation, rend `-31010`, raison `redaction`, avant l'intention ou
l'événement `retenue` (4.4 pas 4, EX-10.23).

### 6.3 Limites

- Ce que le SDK voit est ce que l'agent lui montre : arguments, résultat,
  requête, réponse et `intent` sont déclaratifs. `effects` déclarés par le SDK
  sont recopiés tels quels après validation de forme (CT-1 §5.3) et marqués
  comme déclarés dans le journal d'exploitation.
- Le SDK ne corrèle pas lui-même appel et échange : la règle 5.6 s'applique
  côté démon si l'agent a déclaré ses échanges de modèle par `echangeModele`.
- Un agent compromis peut ne pas appeler le SDK, appeler `finAppel` avec un
  faux résultat, ou déclarer un faux `intent` : seul le pare-feu (EX-6.2) borne
  le premier cas ; les deux autres restent possibles et sont la raison pour
  laquelle le SDK est dit « faible » dans l'architecture.

### 6.4 Langages de la version 0

**EX-6.5** La version 0 publie le SDK en **TypeScript/JavaScript** (Node.js 20
ou plus, la version minimale du SDK TypeScript d'Anthropic, R4 F1.5.11) et en
**Python** (3.10 ou plus, la version minimale d'`openai-agents` 0.24.0 et de
`langchain` 1.4.7, R7 F-52, F-72), parce que ce sont les deux langages des
hôtes et des cadres d'agents de la section 19. Les deux SDK partagent les
vecteurs de l'annexe B (`pieces-mcp`, `redaction` : le SDK ne calcule rien,
mais ses tests vérifient que le démon rend les références attendues).

## 7. Construction de l'événement CT-1 depuis la capture

### 7.1 Principe

Le noyau construit un objet à quinze clés (l'événement sans `hash` ni `sig`),
dans l'ordre de présentation de CT-1 §5.1, puis le scelle : `hash =
SHA-256(P_H ‖ JCS_v0(E'))`, `sig = Ed25519(P_S ‖ JCS_v0(E'))` (CT-1 §6.1,
§6.2 ; `scellerEvenement` de l'implémentation de référence). Les tables
ci-dessous disent, pour chaque sorte, d'où vient chaque champ. Un champ noté
« constante » ne dépend pas de la capture.

**EX-7.1** L'événement construit DOIT valider contre
`spec/schemas/evenement-v0.schema.json` et passer les contrôles E-1 à E-7 de
CT-1 §11.4 **avant** d'être signé ; un événement qui échoue n'est pas signé,
l'appel entre en mode dégradé (section 14) et le défaut est consigné : il
s'agit d'un bogue de l'enregistreur, jamais d'une donnée d'entrée (toute
donnée d'entrée est bornée avant, tronquée ou refusée par les règles des
sections 4 à 6).

### 7.2 Champ par champ, sorte par sorte

**Enveloppe (toutes sortes).**

| Clé | Valeur |
|---|---|
| `version` | constante `0` |
| `seq` | `seq` du dernier événement durable du journal + 1 (7.3) |
| `ts` | horloge murale de l'enregistreur à l'instant de la construction, règle 7.4 |
| `org_id`, `journal_id` | ceux du journal (configuration) |
| `recorder_key_id` | identifiant de la clé courante du signataire (section 11) |
| `prev_hash` | `hash` du dernier événement durable ; `0x00…00` pour `seq = 1` |

**`delegation`.**

| Sous-champ | Frontal MCP, frontal modèle | SDK | Événements du journal sur lui-même |
|---|---|---|---|
| `launched_by` | Configuration de l'entrée de connexion d'hôte (`mcp.hosts`, `model.hosts`) : chaîne fixe, ou `${peer_user}` (utilisateur du processus connecteur, stdio) ou `${oauth_subject}` (sujet du jeton, HTTP) | idem (entrée de `sdk.hosts`) | `"noortrace-enregistreur"` (CT-1 §5.3) |
| `on_behalf_of` | Déclaré (frontal MCP : `_meta["noortrace/delegation"].on_behalf_of` ; frontal modèle : en-tête `X-Noortrace-On-Behalf-Of`) si l'entrée a `accept_declared_delegation: true` **et** si la valeur figure dans sa liste `allowed_on_behalf_of` ; sinon la valeur de configuration `on_behalf_of` ; sinon `null` | paramètre d'`ouvrir`, mêmes conditions | `null` |
| `scope` | Configuration de l'entrée (obligatoire, 1–1024) | idem | `"journal:administration"` (CT-1 annexe A) |
| `run_id` | Déclaré (frontal MCP : `_meta["noortrace/delegation"].run_id` ; frontal modèle : en-tête `X-Noortrace-Run-Id`) si l'entrée a `accept_declared_delegation: true` et si la valeur passe EX-7.2 ; sinon : hôte MCP hérité, identifiant de session MCP du frontal (par processus connecteur ou par `Mcp-Session-Id`) ; sinon `null` | paramètre d'`ouvrir`, mêmes conditions | `null` |

**EX-7.2** La délégation déclarée par l'hôte (`_meta["noortrace/delegation"]`
côté MCP, en-têtes `X-Noortrace-Run-Id` et `X-Noortrace-On-Behalf-Of` côté
passerelle, paramètres d'`ouvrir` côté SDK) est **déclarative** : le frontal
ne la vérifie pas et consigne qu'elle est déclarée. Elle est en ligne dans
chaque événement, donc dans la chaîne signée et dans tout dossier, et ne
peut pas être purgée : elle est donc **bornée avant d'y entrer**. Un `run_id`
déclaré n'est admis que s'il respecte `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`
et si aucun détecteur de texte de la politique de rédaction (ceux de toutes
ses règles, quels que soient leur portée, leurs outils et leur `path` : la
chaîne est la racine et `path` n'est pas résolu) n'y trouve de
correspondance ; un
`on_behalf_of` déclaré n'est admis que s'il figure, octet pour octet, dans
`allowed_on_behalf_of` de l'entrée de connexion d'hôte (une liste fixée par
le client : aucune valeur libre de l'hôte n'entre dans la chaîne). Une
valeur refusée est remplacée par la règle de la table ci-dessus, et le refus
consigné, sans la valeur. `launched_by` et `scope` ne sont jamais pris de
l'hôte : ils viennent de l'identité de la connexion d'hôte et de la
configuration. La clé `_meta` est `noortrace/…` (préfixe à un seul label,
admis par la règle des clés `_meta` qui n'impose la notation DNS inversée
qu'en SHOULD, page Overview 2026-07-28, R1 Q4).

**EX-7.3** La configuration DOIT donner, pour chaque connexion d'hôte
possible (chaque hôte HTTP authentifié du frontal MCP ou de la passerelle,
chaque utilisateur système autorisé à lancer le connecteur ou le SDK, chaque
plage d'adresses sources en modes `icap` et `miroir`), une entrée de
`mcp.hosts`, `model.hosts` ou `sdk.hosts` avec `launched_by`, `scope` et
`host_group` ; une connexion sans entrée est refusée (EX-5.8 pour la
passerelle). Une entrée de `model.hosts` PEUT reprendre le jeton statique
d'une entrée de `mcp.hosts` ; les deux restent deux entrées, reliées par leur
`host_group`.

**`code`.**

| Sous-champ | Appel d'outil (MCP, SDK) | Échange de modèle | Journal sur lui-même, décision |
|---|---|---|---|
| `model` | corrélation 5.6 : échange correspondant, sinon `null` ; appel relayé après approbation : celui de l'appel retenu (EX-7.12) | `<libellé>/<model>`, le `model` étant lu dans la réponse **rédigée** (à défaut dans la requête rédigée, EX-5.7), de sorte que les détecteurs de la portée s'y sont appliqués (EX-5.19) ; `hote/<model>` pour un sampling (EX-4.29) | `null` ; pour une décision d'approbation, ceux de l'appel retenu (CT-1 annexe A seq 3 reprend ceux de seq 2) |
| `prompt_version` | corrélation 5.6, sinon `null` | SHA-256 de la pièce « prompt système » rédigée (8.2), `null` sans prompt système | `null` ; décision : ceux de l'appel retenu |
| `policy_version` | `version` de l'ensemble de politique en vigueur (section 15) | idem | idem |
| `recorder` | version du logiciel de l'enregistreur (chaîne 1–64, celle de `serverInfo`) | idem | idem |

**`intent`.**

| Appel d'outil (MCP) | Appel d'outil (SDK) | Échange de modèle | Décision, rotation, politique |
|---|---|---|---|
| Texte de l'assistant corrélé (5.6), tiré de la réponse rédigée, chaîne ≤ 4096 ou référence (EX-5.21) ; `null` sans corrélation ; appel relayé après approbation : celui de l'appel retenu (EX-7.12) | `intent` déclaré par `debutAppel`, rédigé par les règles de portée `arguments` comme une pièce texte, mêmes bornes ; `null` | Texte produit par l'assistant, tiré de la réponse rédigée (5.5, EX-5.21) | `null` (CT-1 §5.3) |

**`policy` — point d'appel de CT-3.**

**EX-7.4** Avant tout relais d'un appel d'outil (pas 3 de 4.4 ; `debutAppel`
du SDK), le noyau envoie au service d'approbation le message `evaluer` (CT-3
§12.3), dont le corps est exactement l'objet
`{ "tool_announced", "tool_original", "server_alias", "arguments" (valeur en
clair), "class", "delegation", "intent", "code", "context": [références] }`
(`$defs/requete_evaluer` de `ticket-v0`), et reçoit
`{ "rule", "decision", "ticket", "ticket_state", "approval", "approver_set" }`
(`$defs/reponse_evaluer` ; `rule` et `ticket` dans les formes de CT-1 §5.3,
`decision` ∈ {`autorise`, `a_approuver`, `refuse`}, `ticket_state` ∈
{`nouveau`, `en_attente`, `approuve`, `refuse`, `expire`} ou `null`,
`approval` objet de CT-1 §5.3 scellé ou `null`, `approver_set` jeu déclaré
ou `null`). Le noyau applique la réponse selon EX-7.16. Le service répond
dans `policy.timeout_ms` (défaut 2 000) ; sans réponse, avec une réponse
invalide ou avec une erreur, l'appel est traité selon la section 14
(service d'approbation indisponible : bloquant pour `ecriture` **et pour
tout outil susceptible d'approbation**, passant pour les autres lectures
avec `decision: "autorise"` et `rule: null`, le défaut étant consigné).
CT-2 n'évalue pas les règles d'approbation (CT-3 §6) : il les valide au
chargement (EX-15.4 pas 3), et l'ensemble des **outils susceptibles
d'approbation** est fourni par le service au message `charger` (EX-7.15) :
c'est la liste `CANDIDATS` de CT-3 EX-4.11, qui comprend les outils qu'une
règle peut soumettre à approbation **ou refuser**, quels que soient leurs
arguments ; elle est consignée (`approval_candidates`) et tenue en mémoire
avec la politique. Tant qu'elle n'a pas été obtenue (service indisponible
au chargement), **tout** outil est tenu pour susceptible d'approbation, et
un nom annoncé absent de la liste `tools` du dernier `charger` réussi l'est
aussi (CT-3 4.12). Le service d'approbation NE DOIT PAS recevoir la clé du
journal ni écrire d'événement : il rend des décisions, le noyau les scelle.

| Sous-champ | Appel d'outil | Échange de modèle, décision, rotation, politique |
|---|---|---|
| `rule` | celle rendue par CT-3 | `null` |
| `decision` | celle rendue par CT-3 | `"sans_objet"` |
| `ticket` | celui rendu par CT-3 ; recopié dans l'appel relayé après approbation et dans le `refusee` d'un ticket décidé `refuse` ou `expire`, avec `decision: "a_approuver"` et `rule` de l'appel retenu (EX-7.12) | décision d'approbation : le ticket décidé ; autres : `null` |
| `redaction` | nom de la version des règles de rédaction de l'ensemble de politique (`"pii-v1"`) si au moins une référence de l'événement a `redacted: true`, sinon `null` (CT-1 E-4) | idem |

**`approval`.** `null` sauf : décision d'approbation (l'objet construit par
CT-3 et validé par le noyau : `decision`, `ticket`, `request_hash` = `hash`
de l'événement `retenue`, `threshold` lu dans le jeu d'approbateurs,
`approvers`, `signatures` vérifiées par le noyau selon CT-1 §6.3 avant
scellement, `reason` rédigé selon EX-10.24, et `at` **fixé par l'écrivain** égal
au `ts` qu'il attribue à l'événement de décision, EX-7.11 ; `at` n'entre pas
dans l'objet `A` que les approbateurs signent, CT-1 §6.3) ; appel relayé
après approbation, et `refusee` d'un ticket décidé `refuse` ou `expire`
(l'objet de l'événement de décision scellé, clé pour clé, CT-1 A-2).

**EX-7.5** **Vérification d'une remise (SG-).** Le noyau DOIT vérifier
chaque remise (EX-7.19) avant de la sceller, par les vérifications
ci-dessous, dans cet ordre, qui sont celles de CT-3 EX-9.11 et la
vérification SG-7 que la version 0.3 adopte ; à l'intérieur d'une
vérification, les raisons sont essayées dans l'ordre où la dernière colonne
les donne. Un échec refuse la remise (`acquitter` `refuse`, avec la raison
de la première vérification en échec, table de CT-3 §12.8), la consigne
(`approval_remise_refused`, ticket, vérification, raison) et lève l'alerte
de 17.4 ; la décision n'est jamais scellée. Le noyau ne normalise rien : une
signature non canonique est refusée (SG-5), quand le service, lui, la
normalise à la réception d'un vote (CT-3 EX-9.3).

| Id | Vérification | Raison de refus |
|---|---|---|
| SG-1 | La remise a la forme de `ticket-v0` (`$defs/remise`) : `approval` sans `at`, `approval.ticket` égal au ticket de la remise, `remise_id` de la forme `<ticket>/<n>` pour ce ticket, `approver_set` dont la `source` respecte CT-3 EX-8.8 (forme seulement) | `remise_mal_formee` |
| SG-2 | Un événement `retenue` du journal porte `policy.ticket = ticket`, et l'un d'eux a pour `hash` `approval.request_hash` | `ticket_inconnu`, `request_hash_different` |
| SG-3 | Aucune décision n'est scellée pour ce ticket | `ticket_deja_decide` (l'acquittement donne la décision scellée) |
| SG-4 | Pour `approuve` et `refuse` : l'instant d'écriture de la décision, qui sera `approval.at` (EX-7.11), est strictement antérieur à l'échéance `request_ts + E`, où `request_ts` est le `ts` de l'événement `retenue` de `hash` `request_hash` et `E` l'`expire_after_ms` de la version de politique de cet événement (`code.policy_version`, CT-3 EX-7.10) | `echeance_depassee` |
| SG-5 | E-5 et E-9 de CT-1 : même longueur, chaque signature canonique recouvre `approvers[i]` sur `D_A` du `A` de la remise, avec l'`org_id` et le `journal_id` du journal | `signature_invalide` |
| SG-6 | A-3 de CT-1 : approbateurs distincts, membres de `approver_set.members`, `threshold` égal à `approver_set.threshold`, `required ≤ size` et `size` égal au nombre de membres (sinon `seuil_different_du_jeu`), aucun approbateur pour `expire`, au moins `required` pour `approuve` et `refuse` | `approbateur_double`, `approbateur_hors_jeu`, `seuil_different_du_jeu`, `expire_avec_signatures`, `seuil_non_atteint` |
| SG-7 | Séparation des tâches : quand la politique d'approbation de la version de l'événement `retenue` a `separation.self_approval: "interdite"`, aucune adresse de `approvers` n'est une adresse de l'entrée de `separation.identities` dont `launched_by` est égal, octet pour octet, au `delegation.launched_by` de cet événement (CT-3 EX-10.1, EX-10.2) | `auto_approbation` |

SG-7 est normative depuis la version 0.3. Le noyau a ce qu'il faut pour la
faire : la politique de chaque version, pièce de l'ensemble (EX-8.11), et
l'événement `retenue`. Une remise d'un service conforme ne l'échoue jamais,
puisque le service refuse déjà ces votes (CT-3 EX-10.2) ; elle ferme le cas
d'un service compromis qui ferait compter la signature du demandeur, que la
chaîne ne montrerait pas (CT-3 §10.5). Comme la séparation de CT-3, elle ne
voit que les adresses que la politique déclare (CT-3 EX-10.5). Le noyau ne
vérifie pas la fenêtre de contestation, qu'il ne peut pas voir (les votes
restent dans le service, CT-3 EX-9.12).

**`execution`.**

| Sous-champ | Appel d'outil relayé | Appel retenu ou refusé | Échange de modèle | Décision | Rotation | Politique |
|---|---|---|---|---|---|---|
| `tool` | nom annoncé (EX-4.10) ; SDK : nom déclaré | idem | `noortrace.modele.echange` | `noortrace.approbation.decision` | `noortrace.journal.rotation-cle` | `noortrace.journal.politique` |
| `arguments` | référence à la pièce « arguments » (8.2) | idem | référence à la pièce « requête » | référence en ligne à `A` (CT-1 §6.3) | référence en ligne à l'annonce (CT-1 §8) | référence en ligne `{ "policy_version", "policy_sha256" }` (9.1) |
| `status` | `executee` | `retenue` / `refusee` | `executee` | `executee` | `executee` | `executee` |
| `result` | référence à la pièce « résultat » (8.2 ; forme `noortrace_jsonrpc_error` pour une erreur JSON-RPC) | `null` | référence à la pièce « réponse » (8.2 ; forme `noortrace_http_error` pour une erreur HTTP) | `null` | `null` | `null` |
| `duration_ms` | `t_reponse − t_envoi` (4.4) | `null` | `t_reponse − t_envoi` (5.3) | `null` | `null` | `null` |
| `is_error` | `result.isError === true`, ou `true` pour une erreur JSON-RPC, un délai, une annulation, une taille dépassée, une reprise (section 12) | `null` | `true` si statut HTTP ≥ 400, flux incomplet, erreur en flux, délai ; sinon `false` | `null` | `null` | `null` |

**`effects`.**

**EX-7.6** Pour un appel d'outil relayé (`executee`), les effets sont déclarés
dans cet ordre de priorité : (1) le **gabarit d'effets** de l'outil dans la
configuration (`effects: [{ "system", "action", "object": pointeur JSON RFC
6901 dans les arguments ou le résultat (`/arguments/...`, `/result/...`), ou
chaîne fixe, "extract": expression régulière optionnelle (`null` ou chaîne de
1 024 caractères au plus, du sous-ensemble RE2 commun d'EX-10.6) appliquée à
la valeur de `object`, "amount": pointeur ou null, "currency": pointeur ou
chaîne de trois lettres majuscules ou null }]`) ; (2) à défaut de gabarit,
pour une classe `ecriture` : un effet unique `{ "system": <alias>, "action":
"ecriture", "object": <nom d'origine>, "amount": null, "currency": null }` ;
(3) pour une classe `lecture` sans gabarit : `[]`. Un appel `retenue`,
`refusee`, un échange de modèle et une décision ont `effects: []` ; un
événement de politique porte l'effet d'EX-15.6 ; une rotation porte l'effet
de CT-1 §8. Les effets sont « ce que l'enregistreur a vu passer » (CT-1
§5.3), jamais une preuve d'effet.

Évaluation d'un gabarit, dans cet ordre :

1. **Valeurs rédigées.** Les pointeurs `/arguments/…` et `/result/…` sont
   résolus dans les valeurs **rédigées** des pièces « arguments » et
   « résultat » (la valeur JSON dont la pièce est le JCS intégral), jamais
   dans les valeurs en clair : un effet est en ligne dans l'événement, ne
   peut pas être purgé (EX-8.10), et ne peut donc contenir que ce que les
   pièces contiennent. Un pointeur vers un IBAN rédigé donne
   `"[REDIGE:iban]"`. La validation (15.4) avertit quand un pointeur désigne
   un chemin visé par une règle `champ` (la valeur sera un jeton, ou absente
   avec `supprimer`).
2. **Conversion.** Une valeur résolue qui est une chaîne est prise telle
   quelle ; un nombre, un booléen, un objet ou un tableau devient son JCS
   intégral (section 8) ; `null` ou un pointeur qui ne résout pas rend l'effet
   **non résolu**.
3. **Extraction.** Si `extract` n'est pas `null`, il est appliqué à la chaîne
   de `object` ; la **première** correspondance (sémantique leftmost-first)
   donne la valeur : le texte de son premier groupe capturant s'il y en a un
   et qu'il a participé, sinon la correspondance entière ; aucune
   correspondance rend l'effet non résolu.
4. **Bornes de CT-1.** `system` et `object` sont tronqués à 128 et 512 points
   de code ; un `object` vide, un `amount` qui ne respecte pas
   `^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$`, un `currency` hors `^[A-Z]{3}$`, ou
   un couple `amount`/`currency` dont un seul membre est `null`, rendent
   l'effet **invalide**.

Un effet non résolu ou invalide est **omis**, avec une note au journal
d'exploitation (`effect_omitted`, gabarit, raison, sans la valeur) ; il ne
produit jamais un événement invalide : ces valeurs viennent des arguments de
l'agent ou du résultat du serveur, ce sont des données d'entrée, et une
écriture déjà exécutée chez le client DOIT avoir son événement (EX-7.1).
Les effets déclarés par le SDK suivent les pas 2 et 4 après application des
détecteurs de texte de la portée `arguments` à leurs chaînes (EX-6.6).

**`context`.**

**EX-7.7** Pour un appel d'outil par le frontal MCP, `context` contient, dans
cet ordre (EX-4.45) : la pièce de la définition servie à la connexion d'hôte ;
la pièce de la définition courante si elle diffère ; la pièce « liste
annoncée ». Chacune est `{ "sha256", "length", "redacted": false,
"media_type": "application/json", "kind": "autre" }`. La configuration PEUT
retirer les définitions (`tools.definition_in_context: false`) et la liste
(`tools.list_in_context: false`) ; sans les deux, `context` est `[]`. Pour un
appel par le SDK : les références déclarées par `declarerContexte`, dans
l'ordre déclaré. Pour un échange de modèle, une décision, une rotation, une
politique : `[]`. Une pièce de contexte n'est jamais en ligne (CT-1 §5.3) ;
plus généralement, en version 0, **seuls les quatre événements réservés**
portent une référence en ligne (`value`) : leur valeur d'`arguments` (8.2) ;
toute pièce d'appel d'outil, d'échange de modèle ou de contexte est une
référence sans `value`, quelle que soit sa taille (EX-8.3).

### 7.3 `seq`

**EX-7.8** `seq` est attribué par l'écrivain unique du journal (3.4, 13) au
moment où l'événement est ajouté au segment : `seq` du dernier événement
**durable** (écrit et `fsync`) + 1, `prev_hash` = son `hash`. Deux événements
ne sont jamais construits en parallèle pour un même journal ; les frontaux
préparent les pièces en parallèle et remettent au noyau des événements
complets sauf `seq`, `ts`, `prev_hash`, `hash`, `sig`, que l'écrivain fixe
dans l'ordre d'arrivée, et sauf ce qui dépend de `ts` et que l'écrivain
complète après l'avoir fixé : `approval.at` d'une décision (EX-7.11) et
l'annonce `R` d'une rotation, dont `valid_from = ts` (CT-1 §8 ; EX-11.15).
À la reprise après arrêt, le dernier événement
durable est relu depuis le dernier segment (section 12) ; un segment tronqué
est coupé à la dernière ligne complète et valide avant que `seq` reprenne.

### 7.4 `ts` et horloge

**EX-7.9** `ts` est lu sur l'horloge murale (UTC) de l'enregistreur à
l'instant où l'écrivain fixe `seq`, à la milliseconde, puis **`ts = max(ts
lu, ts de l'événement précédent)`** : la chaîne ne décroît jamais (CT-1 §7.1,
règle 4). Si `ts lu < ts précédent − clock.max_backstep_ms` (défaut 5 000),
l'horloge a reculé au-delà du seuil : l'enregistreur entre en mode dégradé
« horloge » (section 14), bloquant pour tout (il ne peut plus dater
honnêtement), jusqu'à ce que l'horloge murale ait rejoint `ts précédent` (ou
que la procédure d'EX-7.13 s'applique). Les durées (`duration_ms`) viennent
de l'horloge monotone et ne sont pas touchées par un recul. Unique exception
à l'instant de lecture : un événement en attente du mode dégradé est scellé
avec `ts = max(captured_at, ts précédent)`, l'instant de sa capture étant
connu (EX-14.10). Une décision d'approbation n'est pas une exception : son
`ts` suit la règle commune, et c'est `approval.at` qui prend la valeur de
`ts` (EX-7.11).

**EX-7.13** **Saut en avant.** Avant de fixer `ts`, l'écrivain compare
l'avance de l'horloge murale depuis l'événement précédent à celle de
l'horloge monotone : si `ts lu − ts lu précédent > (instant monotone −
instant monotone précédent) + clock.max_forward_ms` (défaut 60 000), l'horloge
murale a sauté en avant ; l'écrivain ne date pas l'événement dans le futur,
entre en mode dégradé « horloge » (bloquant pour tout, 14.2) et en sort quand
l'horloge murale est revenue dans la tolérance de l'avance monotone, ou sur
confirmation de l'exploitant (`noortrace-ctl clock --accept`, consignée).
Une source de temps non authentifiée (NTP par défaut) peut être falsifiée :
le client DEVRAIT employer NTS (RFC 8915, non lue pour cette spécification)
ou, à défaut, le démon DEVRAIT comparer à chaque renouvellement de bail son
horloge à celle du magasin de bail quand il en a une (`clock_timestamp()` de
PostgreSQL) et entrer dans le même mode dégradé au-delà de
`clock.max_forward_ms`. Au redémarrage, aucune référence monotone n'existe :
seul le contrôle de recul d'EX-7.9 et la comparaison au magasin de bail
s'appliquent. Si le journal porte **déjà** des `ts` dans le futur (saut non
détecté, par exemple pendant un arrêt) et que l'attente d'EX-7.9 dépasserait
`clock.max_wait_ms` (défaut 3 600 000), l'exploitant clôt le journal : le
démon le ferme à son dernier événement, consigne la rupture, et poursuit dans
un **nouveau journal** (nouveau `journal_id`, `seq = 1`), comme pour la clé
perdue d'EX-11.16 ; les périodes de l'ancien journal jusqu'à celle de son
dernier `ts` sont closes normalement (CT-1 §9, §10).

**EX-7.10** L'enregistreur DOIT utiliser une horloge synchronisée (NTP ou
équivalent du client) et consigner dans le journal d'exploitation tout écart
détecté entre horloge murale et `ts` précédent supérieur à
`clock.warn_skew_ms` (défaut 1 000). `ts` reste déclaratif (CT-1 §15) : la
date est prouvée par les ancres de CT-5, pas par `ts`.

**EX-7.11** Pour un appel retenu, `ts` est l'instant de construction de
l'événement `retenue` ; pour une décision, l'écrivain fixe `ts` par la règle
commune (EX-7.9) **puis** pose `approval.at = ts` : l'instant inscrit est
celui où la décision entre dans la chaîne, après que CT-3 l'a remise (`at`
n'est pas signé par les approbateurs, CT-1 §6.3, de sorte que la poser après
coup n'invalide aucune signature) ; pour l'appel relayé qui suit, `ts ≥
approval.at` (A-2) découle de l'ordre des événements. Avec plusieurs
connexions (EX-13.8), un autre événement peut être scellé entre la remise
de CT-3 et l'écriture de la décision : c'est pourquoi `at` n'est pas lu à la
remise. `period_start ≤ ts < period_end` : un événement construit au
changement d'heure appartient à la période de son `ts`, et la clôture d'une
période n'a lieu qu'après le dernier événement dont le `ts` lui appartient
(CT-1 §10).

**EX-7.12** **Appel relayé après approbation.** L'appel relayé qui porte le
ticket d'un appel retenu dont la décision est `approuve` reprend de
l'événement `retenue` de ce ticket, clé pour clé : `policy.decision`
(`"a_approuver"`), `policy.rule`, `policy.ticket`, `intent`, `code.model` et
`code.prompt_version` ; `approval` est l'objet de l'événement de décision
que le noyau a scellé pour ce ticket (EX-7.11 ; RL-1, EX-7.21), jamais celui
de la réponse du service ; `code.policy_version` est la version en vigueur
au relais. La règle vaut quel que soit le mode d'attente (`retenir` ou
`erreur`, 4.4 pas 6) : en mode `erreur`, la ré-émission de l'agent ne
repasse pas par la corrélation (le bloc `tool_use` a été consommé par
l'appel retenu) et l'appel qui agit garde l'intention de la demande
approuvée. C'est la forme de l'exemple de CT-1 §5.5 (appel relayé `seq 4` :
`decision: "a_approuver"`, `rule` et `ticket` de la demande, `approval`
recopié). La même reprise vaut pour l'événement `refusee` d'un ticket décidé
`refuse` ou `expire` : celui d'une ré-émission reconnue pendant le délai de
reconnaissance (CT-3 EX-7.18) et celui de la décision d'une requête retenue
(EX-4.50) ; il porte l'`approval` de la décision scellée par le noyau,
`effects: []` et `result: null`. C'est la forme que publient les vecteurs de
CT-6 (`valide-decision-refusee`, `valide-decision-expiree`, seq 7).

### 7.5 Échanges avec le service d'approbation

Le noyau échange avec le service d'approbation les messages de CT-3 §12.
Cette section fixe ce qu'il envoie, ce qu'il vérifie avant de sceller une
décision ou de relayer un appel approuvé, et ce qu'il garde. Les formes des
messages sont celles de CT-3 §12 ; le schéma `ticket-v0`
(`spec/schemas/ticket-v0.schema.json`) définit la remise
(`$defs/remise`), la requête et la réponse d'`evaluer`
(`$defs/requete_evaluer`, `$defs/reponse_evaluer`).

**EX-7.14** **Canal.** Le noyau est toujours le client du service : chaque
message est une requête HTTP/1.1 `POST <base>/v0/<méthode>` dont le corps et
la réponse sont un objet JSON (CT-3 EX-12.1), `<base>` étant
`policy.approval.service.url`, ou, quand `url` est nul, la prise
`policy.approval.service.socket` avec la base `http://localhost` ; le canal
est authentifié selon EX-18.8. Le noyau analyse chaque réponse en JSON strict
(4.4 pas 1) ; une réponse illisible ou hors des formes de CT-3 §12 vaut une
erreur du service. Seule l'instance qui détient le bail (section 13) échange
avec le service ; après une bascule ou un redémarrage, elle relit les
fichiers des approbations (EX-12.23), renvoie `charger` (EX-7.15) et
`ouvrir` (EX-7.18), puis ouvre `decisions` (EX-7.19). Chaque message a le
délai `policy.approval.timeout_ms`, `decisions` le délai `wait_ms +
timeout_ms` ; un message sans réponse est réessayé selon la table de CT-3
§12.7, et un `acquitter`, `consommer` ou `expiration` réessayé porte les
mêmes données (CT-3 EX-7.20).

**EX-7.15** **`charger`.** Au démarrage (EX-15.4 pas 6), à chaque
rechargement de l'ensemble de politique (EX-15.5) et à chaque changement de
la liste agrégée des outils (EX-4.15), le noyau envoie `charger` :
`{ "org_id", "journal_id", "environment", "policy_version",
"policy_sha256", "approval", "tools", "requesters" }`, avec les identifiants
du journal, `recorder.environment`, la version et l'empreinte de
l'événement de politique qui annonce l'ensemble (EX-8.11), le membre
`/policy/approval` **sans** `service` (qui porte des références de secrets),
la liste agrégée, triée par `tool_announced` (unités UTF-16, CT-1 §4),
d'objets `{ "tool_announced", "tool_original", "server_alias", "class",
"effects" }` (`effects` : le gabarit d'effets de l'outil, EX-7.6, ou `null`),
et `requesters`, la liste triée de la même façon, sans doublon, des valeurs
**fixes** de `launched_by` des entrées de `mcp.hosts` et de `sdk.hosts` (les
gabarits `${peer_user}` et `${oauth_subject}` ne sont pas transmis). Avec
`requesters`, adopté par la version 0.3, le service peut avertir d'un
demandeur configuré sans entrée dans `separation.identities` (CT-3 EX-4.14,
cinquième point) ; ses avertissements vont dans son propre journal, la
réponse n'en porte pas. Réponse : `{ "policy_version", "policy_sha256",
"approval_candidates" }` ; le noyau vérifie que la version et l'empreinte
sont celles qu'il a envoyées, consigne `approval_candidates` et la tient pour
la liste des outils susceptibles d'approbation parmi les noms envoyés
(EX-7.4). Un nom déclaré par le SDK (`<alias>__<tool>`, EX-6.6) n'est jamais
dans `tools` : il est toujours tenu pour susceptible. L'erreur
`politique_invalide` (`data.errors`) est consignée et lève l'alerte de 17.4 ;
tout outil reste susceptible (CT-3 EX-4.2) ; elle ne devrait pas survenir
après la validation d'EX-15.4 pas 3.

**EX-7.16** **Réponse d'`evaluer`.** Le noyau DOIT vérifier que la réponse
a exactement les six membres de CT-3 §12.3, dans un ordre quelconque (l'ordre
des membres d'un objet JSON n'a pas de sens : un service qui sérialise en JCS
les écrit dans l'ordre alphabétique), `rule` étant une chaîne ou `null`, non
nul pour `a_approuver` (CT-1 §5.3), et qu'elle est l'une des combinaisons de
la table ci-dessous (CT-3 EX-7.16, EX-12.6), avec `ticket` non nul si et
seulement si `ticket_state` l'est, `approver_set` non nul pour `nouveau`
seulement et alors **exploitable** (la forme de `$defs/approver_set` que
vérifie SG-1, `source` de la forme de CT-3 EX-8.8, membres distincts et la
cohérence que vérifie SG-6 : `threshold.size` égal au nombre de membres,
`threshold.required` au plus `size`), et, pour une décision scellée,
`approval.ticket = ticket` et `approval.decision = ticket_state` ; pour une
décision scellée encore, l'`approval` de la réponse DOIT être égal, clé pour
clé, à celui de la décision que le noyau a lui-même scellée pour ce ticket,
et le noyau DOIT en avoir scellé une (RL-1). Un jeu exploitable est ce qui
permet au noyau d'expirer seul le ticket par une décision conforme à A-3 de
CT-1 (EX-9.4). Il l'applique ainsi :

| `decision` | `ticket_state` | `approval` | Le noyau |
|---|---|---|---|
| `autorise` | `null` | `null` | relais (4.4 pas 4, 7 à 14), `policy.decision: "autorise"` |
| `refuse` | `null` | `null` | événement `refusee` ; refus par la politique (EX-4.49) |
| `a_approuver` | `nouveau` | `null` | EX-7.17, événement `retenue` (sauf `retenue` sans décision déjà durable pour ce ticket, 4.4 pas 6), fichiers des approbations (EX-12.23), `ouvrir` (EX-7.18), mode d'attente (4.4 pas 6) |
| `a_approuver` | `en_attente` | `null` | aucun événement, `approval_pending` consigné ; signal `en_attente`, ou rétention (EX-4.50) |
| `autorise` | `approuve` | décision scellée | RL-1 à RL-4 (EX-7.21), relais avec la reprise d'EX-7.12, puis `consommer` (EX-7.20) |
| `refuse` | `refuse` ou `expire` | décision scellée | événement `refusee` qui reprend la `policy` de la `retenue` (EX-7.12) ; signal de même `state` |

Toute autre réponse est invalide : le noyau la consigne
(`approval_response_invalid`) et la traite comme une indisponibilité du
service (14.2 : `-31010`, raison `approbation`, jamais un relais). Une
erreur du service (CT-3 §12.8) l'est aussi : `non_pret` ;
`politique_inconnue`, après un `charger` et un seul nouvel essai
d'`evaluer` ; `plafond_atteint`, qui ne survient que pour une demande que la
politique retiendrait (CT-3 EX-14.1) ; toute autre.

**EX-7.17** **Refus de sceller la `retenue` d'un ticket décidé.** Avant de
sceller l'événement `retenue` d'une réponse `nouveau`, le noyau DOIT
vérifier qu'aucune décision n'est scellée dans le journal pour ce ticket,
quelle que soit la demande qui l'a créée. Sinon, il ne scelle rien, rend
`-31010` (raison `approbation`), consigne `identifiant_en_collision`
(ticket, `seq` de la décision) et lève l'alerte de 17.4 : un identifiant
réattribué par un service qui a perdu son état (contre CT-3 EX-7.1) ne doit
pas attacher la décision scellée d'une autre demande à une nouvelle
`retenue` (CT-3 14.2). Le noyau ne scelle pas non plus de `retenue` pour un
ticket dont une `retenue` sans décision est déjà durable dans le journal : le
service qui répond `nouveau` garde le ticket en `reserve` faute d'avoir reçu
`ouvrir` (lent ou en échec), et chaque ré-émission scellerait sinon une
nouvelle `retenue` (CT-3 EX-7.19 : un agent qui réessaie ne doit pas
remplir le journal) ; le noyau renvoie `ouvrir` pour la `retenue` durable,
rend le signal `en_attente` (ou retient la requête, EX-4.50) et consigne
`approval_pending` (4.4 pas 6). Deux `retenue` sans décision pour un même
ticket ne naissent donc que d'une course, quand une seconde réponse
`nouveau` arrive avant que la première `retenue` soit durable (CT-3
EX-7.19), et restent admises. L'index des décisions par ticket est celui de
SG-3 ; il se dérive de la chaîne à la reprise (12.4). Cette règle, proposée
par CT-3 §15.2, est adoptée par la version 0.3.

**EX-7.18** **`ouvrir`.** Quand un événement `retenue` et sa ligne des
fichiers des approbations sont durables (4.4 pas 6, EX-12.23), le noyau
envoie `ouvrir` : `{ "ticket", "request_hash", "request_seq",
"request_ts", "request_event", "arguments_piece" }`, soit l'identifiant, le
`hash`, le `seq` et le `ts` de l'événement, l'événement lui-même tel que
scellé (objet à dix-sept clés), et les octets de la pièce « arguments »
rédigée en base64 (RFC 4648 §4, avec remplissage), ou `null` quand la
référence est en ligne (ce qui n'arrive pas pour un appel d'outil, EX-7.7).
Le service s'en sert pour la console (CT-3 EX-9.6). Le noyau réessaie
jusqu'au succès et, au redémarrage ou après une bascule, renvoie `ouvrir`
pour tout événement `retenue` dont le ticket n'a pas de décision dans le
journal (CT-3 EX-7.25). La réponse `{ "ticket", "state", "deadline" }` est
consignée. L'erreur `ticket_deja_ouvert` (une autre `retenue` du même ticket
a été remise d'abord) est consignée sans autre effet ; `ticket_inconnu`
(service qui a perdu son état) conduit le noyau à expirer lui-même le ticket
(EX-9.4).

**EX-7.19** **`decisions` et `acquitter`.** Le noyau tient en permanence une
requête `decisions` ouverte, `{ "wait_ms": 25000 }` (au plus 25 000), et la
relance dès qu'elle répond ; sans réponse au terme de `wait_ms +
timeout_ms`, le service est indisponible (CT-3 EX-12.8). Pour chaque remise
reçue, dans l'ordre de la réponse :

1. en mode dégradé (section 14), le noyau répond `acquitter` `temporaire`
   (`reason: "mode_degrade"`), consigne `approval_deferred`, n'inscrit rien
   et ne scelle rien : le stockage est peut-être précisément ce qui est en
   panne, et CT-3 représente la remise (T12) ;
2. sinon, il inscrit la remise dans les fichiers des approbations et
   `fdatasync` (EX-12.23) ; un échec de cette écriture fait entrer le noyau
   en mode dégradé « stockage » et donne le point 1 ; puis il applique
   SG-1 à SG-7 (EX-7.5) ; un échec donne `acquitter` `refuse` avec la raison
   et, pour `ticket_deja_decide`, `seq`, `hash`, `at`, `decision` et
   l'`approval` de la décision scellée ;
3. sinon, il scelle l'événement `noortrace.approbation.decision` (9.1 ;
   `approval` de la remise, `reason` rédigé selon EX-10.24, `at` posé par
   l'écrivain, EX-7.11) : l'écrivain, après l'avoir signé et avant de
   l'ajouter au segment, inscrit la décision dans les fichiers des
   approbations et `fdatasync` (EX-12.23), puis l'ajoute, `fsync` ; le noyau
   répond alors `acquitter` `scelle` avec `seq`,
   `hash`, `at`, `decision`, l'`approval` scellé (avec `at` et
   `request_hash`) et `held`, vrai si et seulement si le noyau retient une
   requête de ce ticket et va la relayer (EX-4.50).

La requête `acquitter` est `{ "remise_id", "ticket", "result", "reason",
"seq", "hash", "at", "decision", "held", "approval" }`, membres non
applicables à `null` (CT-3 EX-12.9). La réponse `{ "ticket", "state" }` est
consignée.

**EX-7.20** **`consommer`.** Après le scellement durable du **premier**
événement `executee` qui porte l'approbation d'un ticket, celui du relais qui
a passé RL-3 (appel relayé, `finAppel`, requête retenue relayée, événement en
attente scellé à la sortie du mode dégradé, événement de reprise de 12.5), le
noyau envoie `consommer` : `{ "ticket", "seq", "hash" }` de cet événement ;
réponse `{ "ticket", "state": "consomme" }` (CT-3 EX-12.10). Les événements
`executee` des continuations MRTR qui héritent de l'approbation (EX-4.21)
portent aussi l'approbation mais ne donnent pas de `consommer`. Le message ne
retarde jamais la réponse à l'hôte ; sans réponse, il est réessayé (CT-3
§12.7). Une réponse `state` `consomme`, ou `clos` (consommation tardive :
relais scellé après la fin du délai de reconnaissance, CT-3 T22), ou une
erreur `requete_invalide` ou `ticket_inconnu`, est **finale** : elle est
consignée (`approval_consume_final`, ticket, état ou raison) et met fin aux
essais ; une autre erreur est réessayée. Au redémarrage, le noyau renvoie
`consommer` pour le premier événement `executee` de chaque ticket dont
l'approbation est portée par un événement du journal et dont le délai de
reconnaissance (`approval.at + E`) court encore : le message est idempotent
(CT-3 EX-7.20).

**EX-7.21** **Vérifications de relais (RL-).** Avant l'intention (4.4 pas 8,
ou celle de `debutAppel`) d'un appel dont la réponse d'`evaluer` est
`autorise` avec `ticket_state: "approuve"`, avant de relayer une requête
retenue dont la décision `approuve` vient d'être scellée (EX-4.50), et avant
de relayer une continuation MRTR qui hérite de l'approbation d'un ticket
(EX-4.21), le noyau DOIT faire, dans cet ordre, les vérifications
suivantes. Un échec refuse le
relais par `-31010` (raison `approbation`), sans intention ni événement, le
consigne (`approval_relay_refused`, ticket, vérification) et lève l'alerte
critique de 17.4. Elles ne lisent que la chaîne, les fichiers des
approbations et les intentions ouvertes.

| Id | Vérification |
|---|---|
| RL-1 | Le noyau a scellé une décision pour ce ticket ; elle est `approuve` ; l'`approval` qu'il relaie est le sien (EX-7.12) ; pour un relais issu d'une réponse `autorise`/`approuve` d'`evaluer`, l'`approval` de la réponse lui est égal clé pour clé (EX-7.16) — une requête retenue ou une continuation n'a pas de réponse d'`evaluer` à comparer. |
| RL-2 | L'appel est la demande approuvée : égalité, avec l'événement `retenue` dont le `hash` est `approval.request_hash`, de `execution.tool`, de `delegation.launched_by`, `delegation.on_behalf_of` et `delegation.scope` (jamais `run_id`, déclaratif), de la référence de la pièce « arguments » (`sha256`, `length`, `redacted`), et du MAC de relais des arguments en clair (EX-7.22) avec celui inscrit pour cette `retenue`. |
| RL-3 | L'approbation n'a pas servi : aucun événement `executee` du journal ne la porte (`approval.ticket` égal au ticket ; événements de reprise et en attente compris), aucune intention ouverte ne porte ce ticket, et aucun autre relais en cours de ce ticket n'a passé RL-3. Pour une continuation MRTR (EX-4.21), dont le premier relais porte déjà l'approbation, RL-3 devient : le `sha256` de son `requestState` est inscrit pour ce ticket (ligne `continuation`, EX-12.23), n'a pas servi (aucune ligne `continuation_consommee`) et aucune autre continuation en cours de ce `requestState` n'a passé RL-3 : au plus un relais par aller-retour MRTR. |
| RL-4 | L'approbation est dans son délai, avec la marge du délai de l'outil : l'instant de la vérification (horloge murale, règle 7.4) plus le `timeout_ms` de l'outil (EX-4.22) est strictement antérieur à `approval.at + E`, `E` étant l'`expire_after_ms` de la version de politique de l'événement `retenue` ; un appel relayé finit ainsi, même au bout de son délai, avant la fin du délai de reconnaissance. |

Ces vérifications, proposées par CT-3 §15.2, sont adoptées par la version
0.3 : elles sont la défense du noyau contre un service compromis qui ferait
relayer, sous une approbation scellée, un autre appel ou le même deux fois
(« blanchiment », CT-3 14.2 et 14.5), ce que la chaîne ne montrerait pas si
seul un champ rédigé changeait. En mode `retenir`, RL-2 compare la requête
retenue à la `retenue` (pour la ré-émission retenue d'EX-4.50, son propre
MAC) et s'applique quand même. Un relais qui a passé RL-3 puis échoue avant
le pas 9 ne libère pas l'approbation : le service l'a déjà servie (CT-3
EX-7.17), et CT-3 n'a pas de message pour la libérer. La marge de RL-4 ne
couvre ni l'événement en attente scellé à la sortie du mode dégradé ni
l'événement de reprise : leur `consommer` peut arriver après la fin du délai
de reconnaissance, et CT-3 l'admet (T22, EX-7.20).

**EX-7.22** **MAC de relais.** Pour une réponse `nouveau` ou `approuve`,
pour une ré-émission `en_attente` que le mode `retenir` retient (EX-4.50), et
pour tout appel relayé, dont le résultat peut être `input_required`
(EX-4.21), le noyau calcule, sur les arguments en clair (4.4 pas 3, ou
`arguments` de `debutAppel`) :

```text
M = HMAC-SHA-256( K_relais, UTF-8("noortrace/relais/v0") ‖ 0x00 ‖ JCS_integral(arguments) )
```

où `K_relais` est la suite d'octets de `storage.relay_mac_key` décodée selon
son `encoding` (15.2), d'au moins 32 octets après décodage, tirée au hasard
et distincte de toute autre clé de l'enregistreur. Pour une `retenue`, `M`
est inscrit dans le fichier des MAC avec le ticket et le `request_hash`
(EX-12.23) ; pour un relais, il est comparé à celui de la `retenue` (RL-2),
puis oublié ; pour un appel dont le résultat est `input_required`, il est
gardé dans l'enregistrement de continuation (EX-4.21) et comparé à celui de
la continuation. `M` est une valeur dérivée à clé qu'EX-10.2 admet hors de
la chaîne, des pièces, du journal d'exploitation et des métriques ; il n'est
jamais transmis au service ni consigné. Toutes les instances d'un même
journal (section 13) DOIVENT résoudre `storage.relay_mac_key` vers les mêmes
octets : chaque fichier `mac-<epoch>` commence par une ligne de contrôle
`{ "kind": "controle", "mac" }`, où `mac` est `M` calculé sur la chaîne JSON
`"controle"` (des arguments sont toujours un objet : aucune collision).
Avant de prendre un bail détenu jusque-là par une autre instance (bascule,
13.4), l'instance recalcule cette valeur et la compare à la ligne de
contrôle du dernier fichier `mac-*` de l'instance précédente ; une
différence est une erreur de configuration (`relay_mac_key_mismatch`,
alerte critique de 17.4) : l'instance ne prend pas le bail, plutôt que de
faire échouer RL-2 pour chaque ticket approuvé ensuite. À la reprise d'une
même instance, une différence dit un changement volontaire de la clé
(consigné, `relay_mac_key_changed`). Un changement de `K_relais` fait échouer
RL-2 pour les tickets dont la `retenue` le précède : l'échec est fermé et
consigné ; l'approbation, déjà servie si la réponse était `autorise`, ne se
libère pas : les ré-émissions de la même demande reçoivent `en_attente`
jusqu'à la fin du délai de reconnaissance, `approval.at + E` (CT-3 EX-7.17),
après laquelle une ré-émission est une nouvelle demande. Une pièce
« arguments » au-delà de la borne de temps n'atteint jamais RL-2 pour un
outil susceptible d'approbation : elle est refusée au pas 4 (EX-10.23).

## 8. Sérialisation des pièces

### 8.1 JCS intégral et JCS v0

CT-1 §4 fixe la forme canonique des structures que CT-1 hache : **JCS v0**,
c'est-à-dire la RFC 8785 restreinte aux entiers sûrs. Les pièces, elles,
portent ce que l'agent, l'outil et le modèle ont échangé, nombres flottants
compris ; les refuser ou les convertir en chaînes dénaturerait la pièce. Les
pièces JSON sont donc sérialisées en **JCS intégral**.

**EX-8.1** Le JCS intégral est la RFC 8785 appliquée telle quelle : membres
d'objet triés par nom (unités de code UTF-16), tableaux dans l'ordre, chaînes
sérialisées comme en CT-1 §4 règle 3, littéraux en minuscules, aucun espace,
et **nombres sérialisés par la règle ES6 `Number::toString`** sur la valeur
IEEE 754 double précision la plus proche du texte reçu, `-0` sérialisé `0`.
`JSON.stringify` d'ECMAScript appliqué à un objet dont les clés ont été
triées récursivement produit exactement cette forme : c'est l'implémentation
de référence (fonction `canonicaliserJCSIntegral` de `scripts/lib/journal.mjs`,
livrée avec CT-2, section 22, employée par le générateur de vecteurs de
l'annexe B et rejouée par `test/enregistreur.test.js`).

| Texte JSON reçu | JCS intégral | Remarque |
|---|---|---|
| `1` | `1` | |
| `1.0` | `1` | la valeur, pas le texte |
| `1.50` | `1.5` | |
| `1e3` | `1000` | |
| `1E+2` | `100` | |
| `1e21` | `1e+21` | seuil de la notation exponentielle en ES6 |
| `1e20` | `100000000000000000000` | |
| `-0`, `-0.0` | `0` | |
| `0.000001` | `0.000001` | |
| `0.0000001` | `1e-7` | |
| `5e-324` | `5e-324` | plus petit dénormalisé |
| `9007199254740993` | `9007199254740992` | **perte** : au-delà de 2^53 la double précision ne conserve pas l'entier |
| `123456789012345678901234567890` | `1.2345678901234568e+29` | **perte** |
| `3.141592653589793238462643383279` | `3.141592653589793` | **perte** de décimales |

Ces valeurs sont calculées (Node.js 22, `JSON.stringify(Number(texte))`) et
reprises dans le vecteur `jcs-integral` de l'annexe B avec les nombres de la
table de la RFC 8785.

**EX-8.2** **La forme canonique n'est pas les octets du réseau.** La pièce est
le JCS intégral de la **valeur** analysée, après rédaction ; deux textes JSON
de même valeur donnent la même pièce ; un nombre dont la valeur exacte excède
la double précision IEEE 754 (entier au-delà de 2^53, décimale au-delà de 17
chiffres significatifs) **n'est pas conservé exactement** dans la pièce,
conformément au profil I-JSON (RFC 7493) dont la RFC 8785 adopte la
contrainte. Les octets relayés, eux, sont ceux du réseau (EX-4.20) : la pièce
prouve la valeur à la précision double, pas le texte. Pour les arguments d'un
appel d'outil, un tel nombre est refusé avant relais (EX-4.44) ; la perte ne
peut donc toucher que les résultats, les échanges de modèle et le contexte,
sur lesquels aucune décision de politique ne porte. Une implémentation qui
a besoin de la fidélité au texte (montants à grande précision) le fait côté
outil, en chaînes, comme CT-1 §3 le demande pour les montants.

**EX-8.3** Les structures de CT-1 (événement, manifeste, valeur en ligne
d'une référence) restent en **JCS v0** : un nombre non entier dans une valeur
en ligne rend l'événement invalide (E-2). Le noyau ne met donc jamais en ligne
(`value`) une pièce qui contient un nombre non entier ; il la stocke et la
référence.

### 8.2 Pièce par pièce

| Pièce | Source | Rédaction (portée, section 10) | Sérialisation | `media_type` |
|---|---|---|---|---|
| arguments | valeur de `params.arguments` du `tools/call` (ou de `debutAppel`) ; `{}` si absent | `arguments` | JCS intégral | absent (JSON implicite) |
| résultat | valeur du membre `result` de la réponse JSON-RPC (objet `CallToolResult` entier) ; pour une erreur JSON-RPC, `{"noortrace_jsonrpc_error": <error>}` ; pour un délai, une annulation, une taille dépassée, la même forme avec le code de l'enregistreur (4.4) ; pour une reprise, l'objet de la section 12.5 ; pour un événement en attente dont le résultat a été perdu, l'objet `noortrace_attente` de la section 14.5 | `resultat` | JCS intégral | absent |
| requête | corps JSON de la requête de modèle, le prompt système remplacé par `[REDIGE:prompt-systeme]` si `model.prompt_in_request: "reference"` (défaut), ou laissé en place et rédigé par les règles `prompt_systeme` avec `"inline"` (EX-8.5) ; pour un sampling, `params` de `CreateMessageRequest` ; pour `echangeModele`, `request` | `requete` et, pour le prompt, `prompt_systeme` | JCS intégral | absent |
| réponse | corps JSON de la réponse hors flux, ou forme consolidée (5.4), ou `{"noortrace_http_error": …}` (5.3.1) ; pour un sampling, `CreateMessageResult` ; pour `echangeModele`, `response` | `reponse` | JCS intégral | absent |
| prompt système | texte UTF-8 extrait selon 5.5 | `prompt_systeme` | **octets UTF-8 du texte rédigé**, sans guillemets ni échappement, sans saut de ligne final (c'est la convention de CT-1 §5.5 : `prompt systeme fictif v3`, 24 octets) | `text/plain` |
| intention (`intent` en référence) | texte de l'assistant, extrait de la réponse rédigée (EX-5.21) | déjà rédigé par la portée `reponse` (EX-10.18) | octets UTF-8 du texte | `text/plain` |
| document de contexte | octets remis par `declarerContexte` | `contexte` (règle de 8.3 pour un document non JSON) | JCS intégral si `media_type` est `application/json` ou de suffixe `+json` et que les octets s'analysent, sinon règle de 8.3 | déclaré par l'appelant (assaini, EX-8.7) |
| définition d'outil | objet `Tool` servi ou courant (EX-4.16, EX-4.45) | aucune | JCS intégral | `application/json` |
| liste annoncée | `{"tools": [<définitions servies, dans l'ordre servi>]}` (EX-4.45) | aucune | JCS intégral | `application/json` |
| document d'ensemble de politique | le document JSON de la section 15 | aucune | JCS intégral | `application/json` |
| annonce de politique | `{ "policy_version", "policy_sha256" }` | aucune | **JCS v0**, en ligne (`value`) | — |
| annonce de rotation | CT-1 §8 | aucune | **JCS v0**, en ligne | — |
| objet `A` d'approbation | CT-1 §6.3 | aucune | **JCS v0**, en ligne | — |

**EX-8.4** La pièce « résultat » est le membre `result` **entier** tel que reçu
du serveur d'outils (avant les réécritures de 4.4 pas 14), y compris
`resultType`, `structuredContent` et `_meta` ; une référence de ressource
(`resource_link`) ou une ressource embarquée (`EmbeddedResource`, `blob` en
base64) y figure telle quelle : l'enregistreur ne déréférence rien et
n'extrait rien.

**EX-8.5** Le remplacement du prompt système par `[REDIGE:prompt-systeme]`
dans la pièce « requête » marque la requête `redacted: true` et exige
`policy.redaction` non nul (E-4), même si aucune autre règle n'a joué ; c'est
la forme de CT-1 annexe A seq 1. Avec `model.prompt_in_request: "inline"`, le
prompt reste dans la requête, **rédigé** : chaque chaîne porteuse du prompt
(Anthropic : `system` s'il est une chaîne, ou le `text` de chacun de ses blocs
de type `text` ; Chat Completions : le `content` chaîne, ou le `text` de
chaque partie de type `text`, des messages de rôle `system` et `developer` ;
Responses : `instructions`, et le `content` chaîne, ou le `text` de chaque
partie de type `input_text` ou `text`, des items de rôle `developer` ou
`system`) est remplacée par le résultat des règles de portée
`prompt_systeme` appliquées à cette chaîne seule (la chaîne est la racine) ;
les règles de portée `requete` s'appliquent ensuite au corps entier. La
pièce « prompt système » est produite en plus, sur le texte joint (table de
5.5). Une règle `champ` de portée `prompt_systeme` (EX-10.19) remplace donc
aussi le prompt dans la requête : la protection n'est pas annulée par le
mode `inline`.

**EX-8.6** `code.prompt_version` = SHA-256 des octets de la pièce « prompt
système » (sans préfixe de domaine : CT-1 §5.3, « SHA-256 des octets UTF-8 du
prompt système tel qu'il est conservé chez le client »). Le prompt est rédigé
par les règles de portée `prompt_systeme` avant hachage, et CT-1 §15 explique
pourquoi : un prompt court conservé en clair se retrouve par dictionnaire. La
configuration PEUT, à la place du texte rédigé, désigner le prompt par un
**identifiant de version nommé par le client** (`model.prompt_system:
"named"` : la pièce est alors la chaîne `[PROMPT:<nom de version>]`, par
exemple `[PROMPT:sinistres-v3]`, fournie par la configuration de la connexion
d'hôte ou, si l'entrée l'admet (`accept_declared_delegation`), par
l'en-tête `X-Noortrace-Prompt-Version` de la passerelle ou
`_meta["noortrace/prompt_version"]`, déclaratifs, admis seulement s'ils
respectent `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` et qu'aucun détecteur de
texte de la politique, quels que soient la portée, les outils et le `path`
de sa règle, n'y correspond, EX-7.2) ; cette forme
ne porte aucune empreinte du clair et répond à la recommandation de CT-1 §15,
mais elle ne prouve plus le contenu du prompt, seulement son nom : la
configuration l'assume explicitement, et le défaut reste le texte rédigé.

### 8.3 Pièces non JSON

**EX-8.7** Un corps de **réponse** de modèle qui n'est pas du JSON (corps
d'erreur HTML d'un mandataire, texte, binaire), qui est déclaré JSON mais ne
s'analyse pas (réponse coupée en cours de corps), ou un document de contexte
non JSON, devient une **pièce non JSON** ; une requête de modèle non
analysable n'en devient jamais une (elle est refusée, EX-5.7). Règles :

1. `media_type` est le type de média du `Content-Type` reçu (ou déclaré par
   le SDK), en minuscules, sans paramètres ; sans en-tête, ou si le résultat
   ne respecte pas le motif `type_mime` de CT-1
   (`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`, 127 caractères au plus),
   `application/octet-stream` : une donnée d'entrée ne rend jamais
   l'événement invalide (EX-7.1) ;
2. si les octets sont de l'**UTF-8 valide** (décodage strict ; une marque
   d'ordre d'octets initiale est conservée comme un caractère du texte), les
   règles de rédaction de la portée s'appliquent au texte comme à une pièce
   texte (la chaîne est la racine), **quel que soit le type de média**
   (`application/json`, `*/*+json`, `application/x-ndjson`, `text/*` ou
   autre) ; la pièce est l'UTF-8 du texte rédigé, `redacted: true` si une
   règle a joué, et ses octets sont exactement ceux reçus si aucune n'a joué
   (marque d'ordre d'octets comprise) ;
3. sinon (binaire, ou codage de contenu inconnu, EX-5.9), si au moins une
   règle de rédaction s'applique à la portée, la pièce est le JCS intégral de
   `{"noortrace_non_redigeable": {"content_type": <valeur reçue ou null>,
   "length": <longueur>, "reason": "non_utf8" ou "codage_inconnu" ou
   "budget_redaction"}}`, `redacted: true`, sans `media_type` : un
   contenu qui ne peut pas être rédigé n'est pas stocké, et son empreinte
   n'entre pas dans la chaîne (EX-10.2) ; si aucune règle ne s'applique, les
   octets sont stockés tels quels. `length` est le nombre d'octets du corps
   reçu (requête ou réponse de modèle, document de contexte, corps HTTP) ;
   pour une pièce JSON tirée d'un message JSON-RPC, que la borne d'EX-10.23
   remplace par cette forme (arguments, résultat d'outil), c'est la longueur
   en octets du JCS intégral de la valeur en clair, la sérialisation
   qu'EX-10.16 calcule déjà, une fois, avant la rédaction ; pour une pièce
   texte (prompt système, intention, contexte `text/plain`), la longueur
   UTF-8 du texte.

Un flux SSE dont aucun événement n'a pu être interprété est traité de même
(`text/event-stream`, règle 2), avec `noortrace_flux_incomplet` noté dans le
journal d'exploitation (il n'y a pas de forme consolidée où le poser).

**EX-8.8** Une référence à une pièce JSON n'a pas de `media_type` (CT-1 §3 :
absent, jamais `null`), sauf la définition d'outil, la liste annoncée et le
document de contexte JSON qui portent `application/json` pour que
l'exportateur sache les présenter ; une pièce non JSON porte toujours
`media_type`.

### 8.4 Stockage par `sha256`

**EX-8.9** Chaque pièce est stockée sous le nom hexadécimal de son `sha256`
(sans `0x`), dans le répertoire de pièces du journal (section 12), **avant**
que l'événement qui la référence soit scellé ; deux pièces identiques ne sont
stockées qu'une fois (adressage par contenu) ; une pièce existante n'est jamais
réécrite. `length` est la taille du fichier. Le vérificateur de CT-1 qui
reçoit la pièce la hache et compare (E-6) : la pièce stockée est exactement ce
qui a été haché (CT-1 §5.4).

**EX-8.10** Les pièces PEUVENT être purgées après la rétention (section 12)
sans casser la chaîne : le journal garde les références ; un dossier exporté
après purge déclare la pièce absente. Les pièces de définition d'outil, de
liste annoncée et le document d'ensemble de politique DEVRAIENT être conservés
aussi longtemps que le journal : ils sont petits et portent le sens des
événements.

### 8.5 Hachage de l'ensemble de politique

**EX-8.11** `policy_sha256` = SHA-256 des octets **JCS intégral** du document
d'ensemble de politique (section 15 ; il contient des nombres non entiers
possibles : seuils de montants, délais), sans préfixe de domaine, écrit
`0x…` ; `policy_version` = le membre `version` du document (chaîne 1–128,
nommée par le client). Le document est stocké comme pièce sous ce `sha256`
(8.2), de sorte que le dossier d'un événement de politique puisse l'emporter.
La règle JSON Pointer des sélecteurs de rédaction (section 10) compare les
noms de membres octet par octet sans normalisation Unicode (RFC 6901 §4, R6
section 1.3) : le document est stocké tel quel, jamais normalisé.

## 9. Journal sur lui-même

### 9.1 Les quatre événements réservés et ce qui les déclenche

CT-1 §5.1 réserve quatre noms sous `noortrace.` ; CT-2 n'en ajoute aucun. Ce
qui les produit :

| Événement | Déclencheur | Produit par | Champs notables |
|---|---|---|---|
| `noortrace.modele.echange` | Une requête de modèle et sa réponse par la passerelle, par ICAP (couple REQMOD/RESPMOD corrélé), par le miroir, par un `sampling/createMessage` relayé (EX-4.29), ou par `echangeModele` du SDK | Frontal modèle, frontal MCP, point d'entrée SDK | 7.2 ; toujours `executee`, `is_error` selon 5.7 |
| `noortrace.approbation.decision` | Le service d'approbation (CT-3) remet une décision `approuve`, `refuse` ou `expire` pour un ticket dont l'événement `retenue` existe (EX-7.19) ; ou le noyau expire seul un ticket que le service n'a pas décidé à temps (EX-9.4) | Noyau, sur remise de CT-3 ou seul | `approval` complet, vérifié (SG-1 à SG-7, EX-7.5) ; `approval.at = ts`, posé par l'écrivain (EX-7.11) ; précède tout appel relayé pour ce ticket (A-2) ; `expire` : `approvers` et `signatures` vides |
| `noortrace.journal.rotation-cle` | Rotation planifiée (`signer.rotation.planned_every_days` de la configuration, EX-11.15), rotation d'urgence (commande d'exploitation), fin de validité annoncée par le signataire | Noyau, avec l'ancienne et la nouvelle clé | CT-1 §8 : annonce en ligne, contresignature de la nouvelle clé, `effects` `cle:<new_key_id>` ; le manifeste de la période est signé par la nouvelle clé |
| `noortrace.journal.politique` | Création du journal ; chargement d'un ensemble de politique dont `policy_sha256` diffère du dernier annoncé dans le journal (au démarrage ou au rechargement, section 15) | Noyau, configuration | `arguments.value = { "policy_version", "policy_sha256" }` (8.5) ; `code.policy_version` égal à la nouvelle version |

**EX-9.1** Le premier événement de tout journal (`seq = 1`) DOIT être un
`noortrace.journal.politique` : la version de politique de chaque événement
suivant est ainsi ancrée dans la chaîne. Tout changement de l'ensemble de
politique (règles d'approbation, règles de rédaction, carte des serveurs
d'outils, réglages de panne) DOIT produire un événement de politique **avant**
le premier événement qui porte la nouvelle `policy_version` ; aucun événement
ne porte une `policy_version` qui n'a pas été annoncée dans le journal.

**EX-9.2** Au démarrage, l'enregistreur relit le dernier événement de
politique du journal ; si `policy_sha256` diffère de celui du document
chargé, il produit un nouvel événement de politique avant de servir le
premier appel, à la place que lui donne la séquence d'EX-9.8. S'il ne peut
pas (mode dégradé), il ne sert aucun appel, d'écriture ni de lecture, sous
la nouvelle politique : il sert les lectures passantes sous la dernière
version **annoncée** dans le journal, et aucun appel d'écriture (section
14), de sorte qu'aucun événement ne porte une `policy_version` non annoncée
(EX-9.1).

**EX-9.8** **Ordre des événements au démarrage et à la sortie du mode
dégradé.** Une seule séquence, dans cet ordre : (1) relecture du journal et
troncature d'une fin incomplète (EX-12.10, pas 1 à 4) ; (2) événements de
reprise des intentions restées ouvertes (12.5), dans l'ordre du journal
d'intention ; (3) événements en attente (14.5), dans l'ordre de
`captured_at`, chacun avec la `policy_version` de sa capture (annoncée dans
le journal avant l'arrêt) ; (4) événement de politique, si l'ensemble chargé
diffère du dernier annoncé (EX-9.2, EX-15.4 pas 6) ; (5) ouverture des
frontaux. Les pas 2 à 4 précèdent tout nouvel appel : aucune autre règle
(EX-12.10, EX-14.10, EX-15.4) ne place un événement avant ceux-ci. À la
sortie d'un mode dégradé sans redémarrage, seuls les pas 2 (intentions
devenues scellables, EX-4.46) et 3 s'appliquent, puisqu'un rechargement de
politique est refusé en mode dégradé « stockage » (EX-15.5).

**EX-9.3** Une rotation de clé est produite **avant** la clôture de la période
si la validité de la clé courante expire pendant cette période (CT-1 §10.1 :
la clé qui signe le manifeste est celle en vigueur à la clôture) ; une
rotation d'urgence est immédiate ; la révocation de l'ancienne clé au registre
est du ressort de CT-4 (CT-1 §8 règle 5) et n'est pas un événement.

**EX-9.4** Une décision `expire` (délai d'approbation écoulé sans décision,
CT-1 §5.3) a `approvers: []`, `signatures: []`, `at` = `ts` de l'événement
(EX-7.11). Le noyau la scelle sur remise du service (EX-7.19), avec la raison
fixe que CT-3 EX-7.11 donne à la remise, ou **seul**, quand aucune décision
n'est scellée pour le ticket à son échéance plus `policy.approval.timeout_ms`
(service muet, `ticket_inconnu`, remise `expire` refusée ; CT-3 EX-12.11).
L'échéance est `request_ts + E`, où `request_ts` est le `ts` de l'événement
`retenue` et `E` l'`expire_after_ms` de la version de politique de cet
événement (`code.policy_version`, CT-3 EX-7.10), et non celui de la version en
vigueur. Une expiration par le noyau seul porte la raison fixe `expire par
l'enregistreur, service d'approbation sans reponse` (non rédigée, EX-10.24),
l'`approver_set` de la dernière remise reçue pour ce ticket dont le jeu est
exploitable (EX-7.16 : forme de SG-1, `source` de CT-3 EX-8.8, membres
distincts, `size` égal au nombre de membres, `required` au plus `size`),
quelle que soit sa décision, à défaut celui de la réponse `nouveau`, et pour
`threshold` le `threshold` de cet `approver_set` : une remise refusée par
SG-1 ou SG-6 (une remise `expire` refusée est justement l'un des cas où le
noyau expire seul) ne peut pas donner une décision qui viole A-3 de CT-1. La
règle se recalcule sur les seules lignes des fichiers des approbations
(EX-12.23) ; la réponse `nouveau` portant toujours un jeu exploitable
(EX-7.16), le noyau a toujours de quoi former la décision. Après son
scellement, le noyau l'annonce au service par `expiration` : `{
"ticket", "seq", "hash", "at", "approval" }`, `approval` étant l'objet scellé
(CT-3 EX-12.11). Une expiration atteinte pendant un mode dégradé est scellée à
la sortie du mode, après les événements de reprise et en attente (EX-9.8) ; sa
raison reste l'une des chaînes fixes ci-dessus, et le retard est dit par le
journal d'exploitation (`approval_expired_deferred`), pas par `reason`. L'appel
reste `retenue` ; aucun appel relayé ne suit ; une ré-émission reconnue reçoit
le refus scellé (un événement `refusee` par tentative, EX-7.12) tant que court
le délai de reconnaissance (CT-3 EX-7.18), puis devient un nouvel appel.

L'enregistreur ne produit aucun autre événement sur lui-même : démarrage,
arrêt, bascule de bail, rotation de segment, clôture de période, purge,
mode dégradé et retour à la normale vont dans le journal d'exploitation, et la
clôture de période produit un manifeste, pas un événement (CT-1 §10).

### 9.2 Journal d'exploitation

Le journal d'exploitation est le journal technique de l'enregistreur sur
lui-même : NDJSON, hors chaîne, non signé, local, destiné à l'exploitation
(section 17) et à l'analyse d'incident. Il n'a aucune valeur probatoire et ne
remplace rien de la chaîne.

**EX-9.5** Format : un objet JSON par ligne, UTF-8, `\n`, clés en anglais :

| Clé | Type | Contenu |
|---|---|---|
| `ts` | horodatage RFC 3339 UTC à la milliseconde | horloge murale |
| `level` | `debug`, `info`, `warning`, `error` | |
| `component` | `frontal_mcp`, `frontal_modele`, `sdk`, `politique`, `redaction`, `noyau`, `stockage`, `bail`, `signataire`, `cloture`, `config`, `supervision` | |
| `event` | chaîne `snake_case` | nom de l'événement d'exploitation (`tool_rejected`, `tool_definition_changed`, `relay_out_of_chain`, `correlation`, `child_stderr`, `degraded_enter`, `degraded_exit`, `lease_acquired`, `lease_lost`, `segment_rotated`, `period_closed`, `intent_recovered`, `clock_skew`, …) |
| `org_id`, `journal_id` | hex 32 ou `null` | journal concerné |
| `seq` | entier ou `null` | événement de la chaîne concerné |
| `host` | chaîne ou `null` | identité de la connexion d'hôte |
| `request_id` | chaîne ou `null` | `id` JSON-RPC d'hôte, `request-id` du fournisseur, selon le contexte |
| `data` | objet | détails propres à `event` : alias, codes, tailles, `sha256`, durées, compteurs |

Exemple :

```json
{"ts":"2026-11-03T13:52:41.091Z","level":"info","component":"frontal_mcp","event":"tool_call_relayed","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","seq":4,"host":"agent-sinistres-stdio","request_id":"h-77812-4","data":{"server":"sap","tool_original":"sap.payments.create","tool_announced":"sap.payments.create","upstream_id":"e-000000000041","intent_id":"i-00000000000000000001-000000000041","arguments_sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4","result_sha256":"0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c","duration_ms":412,"is_error":false,"correlation_seq":1,"ticket":"apr-1192"}}
```

**EX-9.6** Ce qui n'y va **jamais** : une pièce en clair ou rédigée (arguments,
résultat, requête, réponse, prompt, contexte), un fragment de pièce, une
valeur d'en-tête `Authorization`, `x-api-key`, `api-key`, `Cookie`, un jeton
OAuth, un secret ou sa référence résolue, un `requestState` ou un
`inputResponses` MRTR, un `content` d'elicitation, la sortie d'erreur d'un
serveur d'outils au-delà de `logging.child_stderr_max_bytes` (défaut 4 096 par
ligne, tronquée, et seulement avec `child_stderr: "texte"`, EX-4.32) ; une
donnée personnelle qui n'est pas déjà dans la délégation configurée. Les
pièces y sont désignées par `sha256` et `length`. Le journal d'exploitation
est une donnée personnelle au sens du RGPD et de la LPD dès qu'il porte
`launched_by` (RGPD art. 4 point 1, LPD art. 5 let. a, R6 § 1.4) ; il est
conservé avec le journal, pour la même durée (EX-12.21 : l'Olico, art. 9
al. 1 let. b ch. 4, demande que « les informations nécessaires (protocoles,
journal de bord des connexions [log files]) [soient] également conservées »,
R5 § 1.9) ; la rotation locale (`logging.keep_files`,
section 17) ne fixe que le nombre de fichiers tenus par le démon, l'archivage
des fichiers tournés avec le journal relevant de CT-8.

**EX-9.7** Le journal d'exploitation est écrit en ajout, tourné par taille
(`logging.rotate_bytes`, défaut 104 857 600) et conservé `logging.keep_files`
fichiers ; en transport stdio, les lignes de niveau `warning` et `error` **qui
concernent la connexion d'hôte de ce connecteur** (son `host`, ses
requêtes) sont aussi écrites sur `stderr` du connecteur, puisque c'est ce que
l'hôte capture (Claude Desktop les met dans `mcp-server-<nom>.log`, R7
F-05) ; une ligne qui concerne un autre hôte, un serveur d'outils ou le démon
lui-même n'y est jamais copiée ; une
indisponibilité du journal d'exploitation n'est **jamais** bloquante pour un
appel : il est consigné en mémoire et l'alerte de la section 17 est levée.

## Annexe A — Un appel d'écriture traverse l'enregistreur, octet par octet

Le scénario est celui de l'exemple de référence de CT-1 : le règlement du
sinistre 2026-77812 par l'outil `sap.payments.create`, soumis à approbation
(règle `paiement > 5000 CHF`), approuvé par les comptes Hardhat 1 et 2, puis
relayé. Journal `(org_id 0xa581…daab, journal_id 0x0e27…c64b)`, clé
`rec-test-01`, mêmes horodatages que CT-1 annexe A. Un seul serveur d'outils
est configuré, d'alias `sap`, préfixe désactivé (EX-4.10) : le nom annoncé est
le nom d'origine `sap.payments.create`, comme dans CT-1 §5.5. L'hôte est de
l'ère moderne (`2026-07-28`), le serveur d'outils aussi, transport stdio des
deux côtés.

Ce qui diffère de CT-1 §5.5, et pourquoi : (1) les pièces sont en JCS intégral
après rédaction (section 8), alors que CT-1 imprimait les arguments et le
résultat dans l'ordre des clés du réseau : les octets et les `sha256` des
pièces changent, donc `hash` et `sig` ; (2) le résultat porte `resultType:
"complete"`, requis par la révision 2026-07-28 ; (3) `context` porte la pièce
de définition d'outil et la pièce « liste annoncée » (EX-4.45, EX-7.7), et non
les deux documents du sinistre, que le frontal MCP ne voit pas (ils relèvent
du SDK, `declarerContexte`) ; (4) la
décision d'approbation est recalculée parce que son `request_hash` change, et
avec elle les signatures EIP-191 des approbateurs. L'événement seq 1 (échange
de modèle) est repris **inchangé** de CT-1 annexe A pour ancrer la chaîne, et
le lecteur peut vérifier les trois événements ci-dessous avec les outils de
CT-1 ; un enregistreur CT-2 aurait produit un seq 1 différent (requête en JCS
intégral, IBAN de la réponse rédigé) et, par EX-9.1, un événement
`noortrace.journal.politique` en tête de journal : la chaîne de cette annexe
est illustrative, ancrée sur celle de CT-1, et la version complète CT-2 de ce
journal, politique en `seq 1`, est le vecteur `evenements` de l'annexe B. Les
deux premières règles de
CT-1 §5.4 sont respectées dans les deux documents : la pièce stockée est
exactement ce qui a été haché, et la rédaction précède le hachage.

Toutes les valeurs ont été calculées avec `scripts/lib/journal.mjs` (clé
dérivée de la graine de CT-1 §13, `scellerEvenement`, `signerApprobation`,
`verifierChaine`) et une implémentation du JCS intégral de douze lignes
(`JSON.stringify` après tri récursif des clés) ; les trois événements valident
contre `spec/schemas/evenement-v0.schema.json` et `verifierChaine` rend
`{ "valide": true, "diagnostics": [] }`.

### A.1 Ce que le frontal MCP reçoit

Ligne reçue de l'hôte (une ligne, 408 octets, saut de ligne final non
compté) :

```json
{"jsonrpc":"2.0","id":"h-77812-4","method":"tools/call","params":{"name":"sap.payments.create","arguments":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"agent-sinistres","version":"1.4.0"}}}}
```

1. **Lecture** (4.4 pas 1). Le connecteur stdio transmet la ligne au démon ;
   le frontal l'analyse en JSON strict et relève que `params.arguments`
   occupe les octets du texte `{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}`
   (104 octets). `_meta` porte les deux champs requis : la requête est
   recevable.
2. **Résolution** (pas 2). Préfixe désactivé : nom annoncé = nom d'origine
   `sap.payments.create`, alias `sap`. La définition courante de l'outil,
   telle qu'annoncée à l'hôte, est :

```json
{"name":"sap.payments.create","description":"Cree un paiement de sinistre dans SAP","inputSchema":{"type":"object","properties":{"claim_id":{"type":"string"},"amount":{"type":"string"},"currency":{"type":"string"},"beneficiary_iban":{"type":"string"}},"required":["claim_id","amount","currency","beneficiary_iban"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false}}
```

   Sa pièce (JCS intégral, 406 octets) :

```text
{"annotations":{"destructiveHint":false,"readOnlyHint":false},"description":"Cree un paiement de sinistre dans SAP","inputSchema":{"additionalProperties":false,"properties":{"amount":{"type":"string"},"beneficiary_iban":{"type":"string"},"claim_id":{"type":"string"},"currency":{"type":"string"}},"required":["claim_id","amount","currency","beneficiary_iban"],"type":"object"},"name":"sap.payments.create"}
```

   `sha256 = 0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a`,
   `length = 406`. La classe de l'outil est `ecriture` (configuration ; la
   description et `readOnlyHint: false` concordent, mais ne décident pas).
   Le serveur `sap` n'annonce que cet outil, et la liste servie à la
   connexion d'hôte par son dernier `tools/list` est la liste courante : la
   définition servie et la définition courante sont la même pièce, et la
   pièce « liste annoncée » (EX-4.45) est le JCS intégral de
   `{"tools":[<définition ci-dessus>]}`, 418 octets, `sha256 =
   0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e`.
3. **Politique** (pas 3). Le service d'approbation reçoit les arguments en
   clair (montant `7400.00` CHF) et rend la réponse d'`evaluer` d'un ticket
   nouveau (EX-7.16), dont l'`approver_set` est ici un jeu `statique`, celui
   d'un enregistreur de développement (en production, le jeu vient du
   registre, CT-3 EX-8.2) :

<!-- schema: ticket/reponse_evaluer -->
```json
{
  "rule": "paiement > 5000 CHF",
  "decision": "a_approuver",
  "ticket": "apr-1192",
  "ticket_state": "nouveau",
  "approval": null,
  "approver_set": {
    "threshold": { "required": 2, "size": 3 },
    "members": [
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    ],
    "source": "jeu statique de la politique 2026-11-01"
  }
}
```

   La réponse n'entre dans aucun événement : les octets et les hachages de
   cette annexe n'en dépendent pas. Le noyau calcule le MAC de relais des
   arguments en clair (EX-7.22). La corrélation 5.6
   trouve l'échange de modèle seq 1 (sa réponse contient un bloc `tool_use`
   de nom `sap.payments.create` dont `input` a le même JCS intégral que les
   arguments en clair) : `intent = "Régler le sinistre 2026-77812 après
   validation des pièces"`, `code.model` et `code.prompt_version` sont ceux
   de seq 1.
4. **Pièce « arguments »** (pas 4). La règle `iban` de `pii-v1` (portée
   `arguments`, action remplacer) détecte `CH9300762011623852957` (longueur 21
   pour `CH`, reste 1 au MOD 97-10, section 10) et le remplace. Valeur
   rédigée, puis JCS intégral, 96 octets :

```text
{"amount":"7400.00","beneficiary_iban":"[REDIGE:iban]","claim_id":"2026-77812","currency":"CHF"}
```

   `sha256 = 0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4`,
   `length = 96`, `redacted = true`. La pièce est écrite sous
   `6cfc43b5…bbb4` dans le répertoire de pièces et forcée sur disque. (Même
   contenu que la pièce de CT-1 §5.5, autres octets : CT-1 l'écrivait dans
   l'ordre `claim_id, amount, currency, beneficiary_iban` et obtenait
   `0x0fb2…aaf9`.)

### A.2 L'appel est retenu

5. **Événement `retenue`** (pas 6). Le noyau construit et scelle seq 2 ;
   `prev_hash` est le `hash` de seq 1 de CT-1 annexe A.

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 2,
  "ts": "2026-11-03T13:41:07.218Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {
    "rule": "paiement > 5000 CHF",
    "decision": "a_approuver",
    "ticket": "apr-1192",
    "redaction": "pii-v1"
  },
  "approval": null,
  "execution": {
    "tool": "sap.payments.create",
    "arguments": {
      "sha256": "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4",
      "length": 96,
      "redacted": true
    },
    "status": "retenue",
    "result": null,
    "duration_ms": null,
    "is_error": null
  },
  "effects": [],
  "context": [
    {
      "sha256": "0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a",
      "length": 406,
      "redacted": false,
      "media_type": "application/json",
      "kind": "autre"
    },
    {
      "sha256": "0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e",
      "length": 418,
      "redacted": false,
      "media_type": "application/json",
      "kind": "autre"
    }
  ],
  "hash": "0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6",
  "sig": "0x1be28038daa9da9bdc0d456dfa5927d592ea798bc2e281de5fc5298b8c03cc7652548b77fda0e8424054a3da6565c90f57f482715a8880bfdd9a4340e6c8d404"
}
```

   L'événement est ajouté au segment, `fsync`. Aucune décision n'était
   scellée pour `apr-1192` (EX-7.17). Le noyau inscrit l'`approver_set` de
   la réponse et le MAC de relais dans les fichiers des approbations,
   `fsync` (EX-12.23), puis remet le ticket au service par `ouvrir`
   (EX-7.18) : `request_hash = 0x793a…1bd6`, `request_seq = 2`,
   `request_ts = "2026-11-03T13:41:07.218Z"`, `request_event` = l'événement
   ci-dessus, `arguments_piece` = les 96 octets du pas 4 en base64,
   `eyJhbW91bnQiOiI3NDAwLjAwIiwiYmVuZWZpY2lhcnlfaWJhbiI6IltSRURJR0U6aWJhbl0iLCJjbGFpbV9pZCI6IjIwMjYtNzc4MTIiLCJjdXJyZW5jeSI6IkNIRiJ9`.
   Ce récit suit le mode `retenir` : la requête `h-77812-4` de l'hôte reste
   ouverte jusqu'à la décision, 693 s plus tard, et rien n'est envoyé au
   serveur d'outils. C'est un récit, pas une configuration à reproduire :
   EX-4.50 exigerait un `hold_timeout_ms` supérieur à 693 s, sous le délai
   de **tous** les hôtes raccordés ; la plupart des hôtes de CT-3 §11.2
   coupent bien avant (5 à 240 s), et seuls des hôtes en stdio le
   permettraient (Claude Code, qui abandonne après 30 minutes d'inactivité ;
   le SDK MCP Python et langchain-mcp-adapters, sans délai de requête par
   défaut). En mode `erreur`, celui de la configuration de
   référence (CT-3 EX-11.1), l'hôte
   reçoit aussitôt le signal d'approbation (EX-4.49), ligne de 359 octets :

```json
{"jsonrpc":"2.0","id":"h-77812-4","result":{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel soumis a approbation ; ticket=apr-1192 ; state=en_attente"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"},"noortrace/approval":{"ticket":"apr-1192","state":"en_attente"}}}}
```

   puis l'agent ré-émet l'appel, et c'est la ré-émission reconnue, rendue
   `autorise` avec `ticket_state: "approuve"` après la décision (EX-7.16),
   qui suit les pas 7 et suivants ; les événements de cette annexe sont les
   mêmes dans les deux modes.

6. **Décision** (9.1). Les approbateurs signent `A` (CT-1 §6.3) :

```text
JCS(A) = {"decision":"approuve","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6","ticket":"apr-1192"}
D_A    = 0x411768329b8c16bdfe32c4a4b5f6993571c2e5d73b55fdf1f19d00fe408408a8
```

| Approbateur | Adresse | Signature `r ‖ s ‖ v` |
|---|---|---|
| Compte Hardhat 1 | `0x70997970c51812dc3a010c7d01b50e0d17dc79c8` | `0xe6d383bce2a360d254823fd70827faef284269ba457832708c70e8956a6c2f4f6066998d2a083029d5816530d1c15b615c15de6504fc8c1a50a15f8bff131fbb1b` |
| Compte Hardhat 2 | `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc` | `0x64a98eee5687a9e5608b528200130c001414401543aaa01211b8b2666100dfbc3050be55d3d024d599e885424fbbd7ae1d05e050e259e1fd440a1e1c32f0fd1b1c` |

   Le noyau vérifie la remise par SG-1 à SG-7 (EX-7.5), dont les deux
   signatures (E-9, SG-5), le seuil 2 sur 3 (A-3, SG-6), `request_hash` (A-4,
   SG-2) et la séparation des tâches (SG-7 : aucune des deux adresses n'est
   déclarée pour le demandeur), puis scelle seq 3, `ts = approval.at`
   (EX-7.11), et l'acquitte (`scelle`, `held: true`, EX-7.19) ; `arguments`
   est la référence en ligne à `A` (JCS v0, 287
   octets, `sha256 = 0x6b5a72c84048bc9578e472c81185536afd446554b17d56ead46c39b717dc00be`) ;
   `hash = 0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371`,
   `sig = 0x3e086991193f3264ce7704946a14b60b638dbd039dcebab04afc079a1a1d5ee3c8f1ad0fdc4120abd9c6e3e728001eaeedb2e2792614f2d814524641e7b02c0d`.
   Hors ces valeurs, seq 3 a exactement la forme de l'événement seq 3 de CT-1
   annexe A (`intent: null`, `policy.decision: "sans_objet"`, `effects: []`,
   `context: []`).

### A.3 L'appel est relayé

7. **Préconditions et intention** (pas 7 et 8). RL-1 à RL-4 passent
   (EX-7.21) : la décision scellée seq 3 est `approuve`, la requête retenue
   est la demande elle-même, aucun appel ne porte encore l'approbation, et
   l'instant est bien avant `approval.at + E`. Bail détenu, signataire et
   stockage disponibles. Le stockage ajoute au journal d'intention
   `intentions/intentions-1.ndjson` (époque du bail 1) la ligne intention
   suivante (EX-12.12 : neuf clés, JCS intégral, 482 octets, `sha256 =
   0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08`),
   `intent_id` étant formé de l'époque et du compteur de l'écrivain,
   `upstream_id` de l'`id` amont du pas 8, `host` de l'`id` de l'entrée de
   connexion d'hôte (`agent-sinistres-stdio`, 15.3), `arguments` de la référence
   complète de la pièce du pas 4 ; puis la ligne de contexte d'intention de la
   section 12.5 (l'événement partiel : `delegation`, `code`, `intent`, `policy`,
   `approval`, `execution` réduit à `tool` et `arguments`, `effects`, `context`,
   tels qu'ils figurent dans seq 4 ci-dessous, `effects` valant `[]`, 1717
   octets) ; et `fsync` :

```json
{"arguments":{"length":96,"redacted":true,"sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4"},"host":"agent-sinistres-stdio","intent_id":"i-00000000000000000001-000000000041","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","ticket":"apr-1192","tool":"sap.payments.create","upstream_id":"e-000000000041","written_at":"2026-11-03T13:52:40.678Z"}
```

   Si l'enregistreur s'arrêtait maintenant, la reprise (section 12)
   produirait un événement `executee`, `is_error: true`, dont la pièce
   « résultat » serait
   `{"intention_sha256":"0xdd28…0b08","noortrace_reprise":"resultat
   inconnu : enregistreur arrete pendant le relais"}`.

8. **Envoi** (pas 9). Ligne écrite sur l'entrée standard du serveur d'outils
   (420 octets ; `id` propre, `params.name` d'origine, `params.arguments`
   recopié octet pour octet depuis la ligne reçue, `clientInfo` de
   l'enregistreur, `protocolVersion` négociée avec ce serveur) :

```json
{"jsonrpc":"2.0","id":"e-000000000041","method":"tools/call","params":{"name":"sap.payments.create","arguments":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}
```

   `t_envoi` est lu sur l'horloge monotone.
9. **Réponse** (pas 11). Ligne lue sur la sortie standard du serveur d'outils
   (158 octets), 412 ms plus tard :

```json
{"jsonrpc":"2.0","id":"e-000000000041","result":{"resultType":"complete","content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false}}
```

10. **Pièce « résultat »** (pas 12). Aucune règle de `pii-v1` ne joue sur le
    résultat. JCS intégral du membre `result`, 109 octets (l'accent de
    `créé` est en clair, UTF-8, deux octets par `é`) :

```text
{"content":[{"text":"Paiement PAY-2026-55120 créé","type":"text"}],"isError":false,"resultType":"complete"}
```

    `sha256 = 0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c`,
    `length = 109`, `redacted = false`, `is_error = false`. (CT-1 §5.5 : même
    contenu sans `resultType`, dans l'ordre du réseau, 85 octets,
    `0x8bbf…9624`.)
11. **Effets** (EX-7.6). Le gabarit de l'outil dans la configuration est
    `{ "system": "SAP", "action": "ecriture", "object":
    "/result/content/0/text", "amount": "/arguments/amount", "currency":
    "/arguments/currency", "extract": "PAY-[0-9]{4}-[0-9]{5}" }`, évalué sur
    les valeurs **rédigées** des pièces « arguments » et « résultat » (EX-7.6 ;
    aucune règle n'y a touché au montant, à la devise ni au texte) :
    `object = "PAY-2026-55120"` (première correspondance de `extract`, sans
    groupe capturant), `amount = "7400.00"`, `currency = "CHF"`.
12. **Événement** (pas 13). Le noyau construit et scelle seq 4 ; l'écrivain
    vérifie le bail, ajoute la ligne au segment, `fsync`, revérifie le bail
    (EX-13.10), lève l'intention `i-00000000000000000001-000000000041`, puis
    le noyau envoie `consommer` (`{ "ticket": "apr-1192", "seq": 4, "hash":
    "0x8e2f…5ca6" }`, EX-7.20).

<!-- schema: evenement -->
```json
{
  "version": 0,
  "seq": 4,
  "ts": "2026-11-03T13:52:41.090Z",
  "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
  "journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "recorder_key_id": "rec-test-01",
  "prev_hash": "0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371",
  "delegation": {
    "launched_by": "u.martin@assureur-demo.example",
    "on_behalf_of": "service-sinistres",
    "scope": "sinistres:lecture,paiement",
    "run_id": "run-2026-11-03-0142"
  },
  "code": {
    "model": "fournisseur/modele@2026-09",
    "prompt_version": "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58",
    "policy_version": "2026-11-01",
    "recorder": "0.1.0"
  },
  "intent": "Régler le sinistre 2026-77812 après validation des pièces",
  "policy": {
    "rule": "paiement > 5000 CHF",
    "decision": "a_approuver",
    "ticket": "apr-1192",
    "redaction": "pii-v1"
  },
  "approval": {
    "decision": "approuve",
    "ticket": "apr-1192",
    "request_hash": "0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6",
    "threshold": {
      "required": 2,
      "size": 3
    },
    "approvers": [
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    ],
    "signatures": [
      "0xe6d383bce2a360d254823fd70827faef284269ba457832708c70e8956a6c2f4f6066998d2a083029d5816530d1c15b615c15de6504fc8c1a50a15f8bff131fbb1b",
      "0x64a98eee5687a9e5608b528200130c001414401543aaa01211b8b2666100dfbc3050be55d3d024d599e885424fbbd7ae1d05e050e259e1fd440a1e1c32f0fd1b1c"
    ],
    "at": "2026-11-03T13:52:40.511Z",
    "reason": "Pièces validées"
  },
  "execution": {
    "tool": "sap.payments.create",
    "arguments": {
      "sha256": "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4",
      "length": 96,
      "redacted": true
    },
    "status": "executee",
    "result": {
      "sha256": "0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c",
      "length": 109,
      "redacted": false
    },
    "duration_ms": 412,
    "is_error": false
  },
  "effects": [
    {
      "system": "SAP",
      "action": "ecriture",
      "object": "PAY-2026-55120",
      "amount": "7400.00",
      "currency": "CHF"
    }
  ],
  "context": [
    {
      "sha256": "0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a",
      "length": 406,
      "redacted": false,
      "media_type": "application/json",
      "kind": "autre"
    },
    {
      "sha256": "0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e",
      "length": 418,
      "redacted": false,
      "media_type": "application/json",
      "kind": "autre"
    }
  ],
  "hash": "0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6",
  "sig": "0x4a952439f1642f828bbdb9b62d6d36e10bfd924749c259f0a821b8ee955d21b0fc5ccc0d9279807ba5a5f420ce349e797b91532b5e79843d1ad9587d83e89200"
}
```

    Forme canonique `C` (JCS v0 de l'événement sans `hash` ni `sig`, 2249
    octets UTF-8) :

```text
{"approval":{"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8","0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"],"at":"2026-11-03T13:52:40.511Z","decision":"approuve","reason":"Pièces validées","request_hash":"0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6","signatures":["0xe6d383bce2a360d254823fd70827faef284269ba457832708c70e8956a6c2f4f6066998d2a083029d5816530d1c15b615c15de6504fc8c1a50a15f8bff131fbb1b","0x64a98eee5687a9e5608b528200130c001414401543aaa01211b8b2666100dfbc3050be55d3d024d599e885424fbbd7ae1d05e050e259e1fd440a1e1c32f0fd1b1c"],"threshold":{"required":2,"size":3},"ticket":"apr-1192"},"code":{"model":"fournisseur/modele@2026-09","policy_version":"2026-11-01","prompt_version":"0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58","recorder":"0.1.0"},"context":[{"kind":"autre","length":406,"media_type":"application/json","redacted":false,"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a"},{"kind":"autre","length":418,"media_type":"application/json","redacted":false,"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e"}],"delegation":{"launched_by":"u.martin@assureur-demo.example","on_behalf_of":"service-sinistres","run_id":"run-2026-11-03-0142","scope":"sinistres:lecture,paiement"},"effects":[{"action":"ecriture","amount":"7400.00","currency":"CHF","object":"PAY-2026-55120","system":"SAP"}],"execution":{"arguments":{"length":96,"redacted":true,"sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4"},"duration_ms":412,"is_error":false,"result":{"length":109,"redacted":false,"sha256":"0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c"},"status":"executee","tool":"sap.payments.create"},"intent":"Régler le sinistre 2026-77812 après validation des pièces","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","policy":{"decision":"a_approuver","redaction":"pii-v1","rule":"paiement > 5000 CHF","ticket":"apr-1192"},"prev_hash":"0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371","recorder_key_id":"rec-test-01","seq":4,"ts":"2026-11-03T13:52:41.090Z","version":0}
```

| Calcul | Valeur |
|---|---|
| `SHA-256(P_H ‖ C)` = `hash` | `0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6` |
| `Ed25519(sk(rec-test-01), P_S ‖ C)` = `sig` | `0x4a952439f1642f828bbdb9b62d6d36e10bfd924749c259f0a821b8ee955d21b0fc5ccc0d9279807ba5a5f420ce349e797b91532b5e79843d1ad9587d83e89200` |

13. **Ligne de segment** (section 12). La ligne ajoutée au segment est le
    JCS v0 de l'événement **complet** (`hash` et `sig` compris, donc dix-sept
    clés triées) suivi de `\n` : 2465 octets, saut de ligne compris. Les clés
    `hash` et `sig` s'intercalent dans l'ordre alphabétique (`hash` entre
    `execution` et `intent`, `sig` entre `seq` et `ts`) :

```text
{"approval":{"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8","0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"],"at":"2026-11-03T13:52:40.511Z","decision":"approuve","reason":"Pièces validées","request_hash":"0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6","signatures":["0xe6d383bce2a360d254823fd70827faef284269ba457832708c70e8956a6c2f4f6066998d2a083029d5816530d1c15b615c15de6504fc8c1a50a15f8bff131fbb1b","0x64a98eee5687a9e5608b528200130c001414401543aaa01211b8b2666100dfbc3050be55d3d024d599e885424fbbd7ae1d05e050e259e1fd440a1e1c32f0fd1b1c"],"threshold":{"required":2,"size":3},"ticket":"apr-1192"},"code":{"model":"fournisseur/modele@2026-09","policy_version":"2026-11-01","prompt_version":"0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58","recorder":"0.1.0"},"context":[{"kind":"autre","length":406,"media_type":"application/json","redacted":false,"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a"},{"kind":"autre","length":418,"media_type":"application/json","redacted":false,"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e"}],"delegation":{"launched_by":"u.martin@assureur-demo.example","on_behalf_of":"service-sinistres","run_id":"run-2026-11-03-0142","scope":"sinistres:lecture,paiement"},"effects":[{"action":"ecriture","amount":"7400.00","currency":"CHF","object":"PAY-2026-55120","system":"SAP"}],"execution":{"arguments":{"length":96,"redacted":true,"sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4"},"duration_ms":412,"is_error":false,"result":{"length":109,"redacted":false,"sha256":"0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c"},"status":"executee","tool":"sap.payments.create"},"hash":"0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6","intent":"Régler le sinistre 2026-77812 après validation des pièces","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","policy":{"decision":"a_approuver","redaction":"pii-v1","rule":"paiement > 5000 CHF","ticket":"apr-1192"},"prev_hash":"0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371","recorder_key_id":"rec-test-01","seq":4,"sig":"0x4a952439f1642f828bbdb9b62d6d36e10bfd924749c259f0a821b8ee955d21b0fc5ccc0d9279807ba5a5f420ce349e797b91532b5e79843d1ad9587d83e89200","ts":"2026-11-03T13:52:41.090Z","version":0}
```

    L'en-tête du segment (jeton de clôture, premier `seq`, journal) précède la
    première ligne du fichier et est décrit en section 12 ; il n'entre dans
    aucun hachage d'événement.

14. **Réponse à l'hôte** (pas 14). Ligne écrite sur la sortie standard du
    connecteur (252 octets) : `id` de l'hôte, `result` recopié depuis la ligne
    du pas 9, `serverInfo` de l'enregistreur ajouté dans `_meta` :

```json
{"jsonrpc":"2.0","id":"h-77812-4","result":{"resultType":"complete","content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}
```

    Le journal d'exploitation reçoit la ligne `tool_call_relayed` de la
    section 9.2 (exemple de cette section : mêmes `sha256`, `seq: 4`,
    `correlation_seq: 1`).

### A.4 Récapitulatif des valeurs de l'annexe

| Grandeur | Valeur |
|---|---|
| Pièce « arguments » (rédigée, JCS intégral) | 96 octets, `0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4` |
| Pièce « définition d'outil » | 406 octets, `0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a` |
| Pièce « liste annoncée » | 418 octets, `0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e` |
| Pièce « résultat » | 109 octets, `0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c` |
| Ligne intention (`intention_sha256`) | 482 octets, `0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08` |
| `hash` seq 1 (CT-1 annexe A, inchangé) | `0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179` |
| `hash` seq 2 (`retenue`) = `request_hash` | `0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6` |
| `D_A` (ticket `apr-1192`) | `0x411768329b8c16bdfe32c4a4b5f6993571c2e5d73b55fdf1f19d00fe408408a8` |
| `hash` seq 3 (décision) | `0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371` |
| `hash` seq 4 (relayé) | `0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6` |
| Longueur de `C` (seq 4) | 2249 octets |
| Longueur de la ligne de segment (seq 4) | 2465 octets, `\n` compris |
| Clé publique `rec-test-01` | `0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045` |

## 10. Rédaction avant hachage

Cette section clôt la décision ouverte 3 de l'architecture (« politique de
rédaction des paramètres sensibles avant hachage », section 20). Elle fixe le
document de politique, ses détecteurs au caractère près, l'ordre d'application
et ce que le journal garde de la rédaction. Les faits externes viennent du
digest R6 (outils de référence, formats des identifiants, RFC 6901, textes de
droit), relus le 2026-10-22.

### 10.1 Principes

**EX-10.1** La rédaction s'applique à la **valeur JSON** d'une pièce (ou à son
texte, pour une pièce `text/plain`) **avant** sa sérialisation en JCS intégral
(section 8) et donc avant tout hachage. Les octets stockés, le `sha256` et la
`length` de la référence (CT-1 §5.4) sont ceux de la pièce rédigée. Il n'existe
pas de pièce « avant rédaction » dans le stockage de l'enregistreur, sauf le
coffre optionnel de 10.7.

**EX-10.2** Le journal, les pièces, le journal d'exploitation et les métriques
NE DOIVENT contenir ni la valeur en clair d'une donnée rédigée, ni un hachage,
un condensé ou un pseudonyme calculé sans clé secrète de cette valeur. Un
hachage sans secret d'un identifiant à faible entropie (IBAN, numéro de
téléphone, nom) se renverse par dictionnaire : c'est la mise en garde du CEPD
(lignes directrices 01/2025 sur la pseudonymisation, § 88 à 90 et note 23,
version pour consultation publique adoptée le 16 janvier 2025, toujours en
cette version au 2026-10-22, R6) et le motif pour lequel Presidio sale par
défaut son opérateur `hash` depuis la version 2.2.361 (R6). La seule forme
dérivée admise est le pseudonyme à clé de 10.3.9, et, hors de la chaîne,
des pièces, du journal d'exploitation et des métriques, le MAC de relais
d'EX-7.22, sous une clé distincte, effacé avec son fichier (EX-12.23). La
règle vaut aussi pour les **valeurs en ligne** de l'événement, qui sont dans
la chaîne signée et dans chaque dossier et ne peuvent pas être purgées :
`intent` (tiré de la réponse rédigée, EX-5.21), `effects` (évalués sur les
valeurs rédigées, EX-7.6), `code.model` (lu dans la réponse rédigée, 7.2),
la délégation déclarée et le nom de prompt déclaré (bornés et soumis aux
détecteurs, EX-7.2, EX-8.6), et le motif `approval.reason` d'une décision
(rédigé avant le scellement, EX-10.24). Aucune valeur en ligne n'est tirée
d'une donnée en clair qui n'a pas traversé la rédaction.

**EX-10.3** Les règles de rédaction sont un **document JSON versionné**
(10.2), validé contre `spec/schemas/politique-redaction-v0.schema.json` au
démarrage et à chaque rechargement (section 15), nommé par son champ `name`
(`"pii-v1"`), repris tel quel dans `policy.redaction` de tout événement dont une
référence porte `redacted: true` (CT-1 §5.3, E-4), et inclus dans l'ensemble de
politique dont `code.policy_version` nomme la version (10.6).

**EX-10.4** La rédaction est **déterministe** : pour une politique, une portée,
un outil et une valeur d'entrée donnés, deux implémentations conformes
produisent les mêmes octets, sauf quand le budget de temps d'EX-10.23 est
dépassé, ce qui dépend de la machine ; hors dépassement, rien de la
rédaction ne dépend du temps. C'est pourquoi les détecteurs de 10.3 sont écrits
au caractère près, avec leur normalisation et leur somme de contrôle, et
pourquoi les vecteurs `redaction` de l'annexe B donnent entrée, politique et
octets attendus.

**EX-10.5** La rédaction porte sur les **chaînes de caractères** de la valeur
JSON. Un nombre, un booléen, `null`, un nom de membre ne sont jamais examinés
ni modifiés par un détecteur de texte : un numéro de carte porté par un nombre
JSON n'est pas détecté (limite dite en 10.8 ; une règle à sélecteur `path` et
détecteur `champ` couvre ce cas quand le client connaît le champ).

### 10.2 Politique de rédaction, version 0

#### 10.2.1 Document

Le document est un objet JSON à la forme suivante (schéma
`spec/schemas/politique-redaction-v0.schema.json`, `$id`
`https://noortrace.example/schemas/v0/politique-redaction.schema.json`) :

| Clé | Type | Règle |
|---|---|---|
| `version` | entier | Constante `0`. |
| `name` | chaîne `^[a-z0-9][a-z0-9.-]{0,127}$` | Nom et version des règles ; c'est la valeur de `policy.redaction`. Toute modification des règles DOIT changer `name` (10.6). |
| `description` | chaîne ≤ 1024, optionnelle | Texte libre. |
| `pseudonym_key` | référence de secret avec `encoding`, ou `null` | Secret HMAC-SHA-256 de l'action `pseudonyme` (10.3.9) ; `null` si aucune règle ne l'emploie. Jamais la valeur. La référence DOIT porter `encoding` (15.2) : `"hex"`, `"base64"` ou `"utf8"`, qui dit comment la valeur résolue devient les octets de `K`. |
| `named_patterns` | objet, optionnel | Expressions régulières nommées (10.3.7) : `{ "<nom>": { "pattern": "<RE2>", "description": … } }`. |
| `rules` | tableau de 1 à 256 règles | Appliquées dans l'ordre (10.4). |

Une règle :

| Clé | Type | Règle |
|---|---|---|
| `id` | chaîne `^[a-z0-9][a-z0-9-]{0,63}$`, unique | Reprise dans le journal d'exploitation (`redaction_applied`, 10.4). |
| `scopes` | tableau non vide, sans doublon, de portées | Pièces visées : `arguments`, `resultat`, `requete`, `reponse`, `prompt_systeme`, `contexte` (10.2.2). |
| `tools` | `"*"` ou tableau de noms | Outils visés : noms annoncés exacts, ou `<alias>__*` pour tous les outils d'un serveur. Pour les portées `requete`, `reponse`, `prompt_systeme`, seule la valeur `"*"` rend la règle applicable (il n'y a pas d'outil). Pour `contexte` par le SDK, le nom est celui de l'appel auquel la pièce est rattachée, `"*"` sinon. |
| `path` | pointeur JSON RFC 6901, optionnel | Si présent, la règle ne porte que sur la valeur désignée : pour un détecteur de texte, toutes les chaînes contenues dans cette valeur (récursivement, dans l'ordre de parcours de 10.4) ; pour `champ`, la valeur elle-même. Si absent, toutes les chaînes de la pièce. Évaluation : RFC 6901 § 4 (`~1` décodé avant `~0`, comparaison des noms octet par octet, aucune normalisation Unicode, R6) ; un pointeur qui ne résout pas rend la règle sans effet pour cette pièce, sans erreur, avec une note dans le journal d'exploitation. Le pointeur est relatif à la **racine de la pièce** : pour `arguments`, l'objet `params.arguments` ; pour `resultat`, l'objet `result` reçu ; pour `requete`, le corps JSON de la requête de modèle ; pour `reponse`, la forme consolidée ou le corps JSON ; pour `prompt_systeme`, la racine est une chaîne (le pointeur vide `""` seul résout) ; pour `contexte`, la valeur JSON de la pièce si elle est JSON, sinon la chaîne de son texte. |
| `detectors` | tableau de 1 à 16 détecteurs | `{ "type": "iban" }`, `{ "type": "avs" }`, `{ "type": "email" }`, `{ "type": "telephone" }`, `{ "type": "carte" }`, `{ "type": "regex", "name": "<clé de named_patterns>" }`, `{ "type": "champ", "label": "<étiquette>" }`. Appliqués dans l'ordre du tableau (10.4). |
| `action` | `{ "kind": "remplacer" }`, `{ "kind": "pseudonyme" }` ou `{ "kind": "supprimer" }` | 10.2.3. |

Contraintes de validation que le schéma n'exprime pas (vérifiées au démarrage
et au rechargement, section 15 ; une politique qui les viole est refusée) :

**EX-10.6** Un détecteur `champ` exige `path` ; `supprimer` exige `path` et un
tableau `detectors` réduit au seul détecteur `champ` ; `pseudonyme` exige
`pseudonym_key` non nul ; chaque `regex` nomme une clé existante de
`named_patterns` ; chaque motif nommé est écrit dans le **sous-ensemble
commun** défini ci-dessous, sémantique « leftmost-first », sensible à la
casse, sans drapeau, pour que l'implémentation de référence (ECMAScript,
drapeau `u`) et le vérificateur (Go, paquet `regexp`) trouvent les mêmes
correspondances ; aucun motif nommé ne fait correspondre l'un des jetons de
remplacement possibles de la politique (`[REDIGE:<t>]`,
`[PSEUDO:<t>:000000000000]` pour chaque type, nom ou étiquette `t` employé) ;
les `id` de règles sont uniques. Le même sous-ensemble vaut pour `extract` des
gabarits d'effets (EX-7.6).

**Sous-ensemble commun ECMAScript/RE2.** Il est défini par une liste
**autorisée**, parce que des constructions admises par les deux moteurs n'y
ont pas le même sens (`\s` reconnaît U+00A0 et U+202F en ECMAScript, pas en
RE2 ; `.` exclut `\r` en ECMAScript, pas en RE2) et que d'autres ne sont
admises que par l'un (`A` en ECMAScript, `\x{41}`, `\A`, `\z` et
`[[:alpha:]]` en RE2). Un motif est admis si et seulement s'il se compose
de :

1. caractères littéraux autres que `\ ^ $ . | ? * + ( ) [ ] { }` ;
2. échappements `\\`, `\^`, `\$`, `\.`, `\|`, `\?`, `\*`, `\+`, `\(`, `\)`,
   `\[`, `\]`, `\{`, `\}`, `\/` ; `\t`, `\n`, `\r`, `\f`, `\v` ; `\xHH`
   (deux chiffres hexadécimaux) ; classes `\d`, `\D`, `\w`, `\W` ;
   frontières `\b`, `\B` ;
3. classes `[…]` et `[^…]` non vides, faites de littéraux (autres que `\`, `]`
   et `[`), d'échappements du point 2 sauf `\b` et `\B`, de `\-`, et
   d'intervalles `a-z` entre deux de ces caractères ; un `-` littéral n'est
   admis qu'en première ou dernière position ;
4. groupes `( … )`, `(?: … )`, `(?<nom> … )` et `(?P<nom> … )` (nom
   `^[A-Za-z][A-Za-z0-9_]{0,31}$`) ;
5. quantificateurs `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}` (`n ≤ m ≤ 1000`,
   `n` et `m` écrits sans zéro non significatif, de la forme
   `0|[1-9][0-9]{0,3}` : RE2 et le paquet `regexp` de Go lisent `a{01}`
   comme le texte `a{01}` quand ECMAScript y voit une répétition, de sorte
   que `[0-9]{04}` rédigerait `1234` en ECMAScript et rien en Go ; un tel
   quantificateur est refusé, « zéro non significatif dans un
   quantificateur »), chacun éventuellement suivi de `?` (paresseux), jamais
   de `+` (possessif) ;
6. ancres `^` et `$` (début et fin de la chaîne, sans mode multiligne) ;
   alternative `|`.

Tout le reste est refusé, notamment `.`, `\s`, `\S`, `\u…`, `\p…`, `\P…`,
`\x{…}`, `\A`, `\z`, `\Q…\E`, `\0` et toute référence `\1`…, `\c…`, les
recherches avant et arrière, les groupes atomiques, les drapeaux en ligne et
les classes POSIX. Le client écrit `[^\n]` à la place de `.` et
`[ \t\n\r\f\v]` à la place de `\s`. Dans ce sous-ensemble, `\d`, `\w` et
`\b` sont ASCII dans les deux moteurs, et `[^…]` admet tout point de code.

**Règles de structure et de taille.** Un motif fait de ces constructions
n'est admis que s'il respecte en outre les trois règles suivantes, vérifiées
à l'identique par l'implémentation de référence et par le vérificateur Go :

a) **aucune répétition imbriquée ou ambiguë** : un quantificateur (de
   quelque forme, paresseux ou non) ne porte pas sur un groupe (capturant,
   non capturant ou nommé) dont le corps contient, à quelque profondeur que
   ce soit, un quantificateur ou une alternative `|`. C'est la forme des
   motifs à retour arrière exponentiel que décrit OWASP, un groupe répété
   dont le corps contient une répétition ou une alternative qui se recouvre
   (`(a+)+$`, `([a-zA-Z]+)*$`, `(a|aa)+$`, `(a|a?)+$`, R10 F-25), qu'une
   borne ne rend pas sûre (`(a|aa){1,1000}$` passe 4 s à 35 caractères,
   R10 F-28) ; une forme bénigne comme `(?:[0-9]{4} ?){3}` s'écrit déroulée ;
b) **aucun groupe quantifié qui peut être vide** : le corps d'un groupe
   quantifié contient au moins un caractère littéral, un échappement de
   caractère ou une classe (`\b`, `\B`, `^`, `$` et un groupe vide ne
   consomment rien), de sorte qu'aucune itération ne correspond à la chaîne
   vide ;
c) **taille développée d'au plus 1 000** : la taille d'un littéral, d'un
   échappement, d'une classe ou d'une ancre vaut 1 ; celle d'une suite ou
   d'une alternative, la somme de ses éléments ; celle d'un groupe, celle de
   son corps ; celle d'un élément quantifié, sa taille multipliée par 1 pour
   `*`, `+` et `?`, par `max(n, 1)` pour `{n}`, par `n + 1` pour `{n,}` et
   par `max(m, 1)` pour `{n,m}`. Le coût d'un moteur à temps linéaire croît
   avec cette taille : le paquet `regexp` de Go met 12 047 ms à parcourir
   10^6 caractères avec `[0-9]{1000}x`, de taille 1 001, refusé (R10 F-29).

La règle a) supprime aussi toute répétition imbriquée, que Go et RE2
bornent seuls (`(a{1,1000}){1,1000}$` était admis par le contrôle
JavaScript et refusé par Go, R10 F-30). Ces règles écartent les groupes
répétés que décrit OWASP ; elles n'écartent ni le retour arrière d'une suite
d'atomes quantifiés, exponentiel dans le nombre de ces atomes (`a?` répété
n fois puis `a` répété n fois), ni le retour arrière polynomial
d'ECMAScript : sans groupe répété, `[0-9]+$` met 4 671 ms sur 80 000 chiffres
suivis de `x`, et `[a-z]*[a-z]*[a-z]*!` plus de 5 s sur 1 000 caractères
(R10 F-27), tous admis. Aucune règle de structure ne borne ce coût, puisqu'un
seul quantificateur suffit à dépasser la borne sur une entrée assez longue :
c'est pourquoi EX-10.23 borne le temps de toute exécution d'un motif, au
démarrage comme sur les données. Un motif admis se compile en Go tel quel ;
en ECMAScript, avec le drapeau `u`, chaque ouverture de groupe nommé
`(?P<nom>` reconnue par l'analyse du point 4 (parenthèse non échappée, hors
classe) étant écrite `(?<nom>`, seule forme de groupe nommé qu'ECMAScript
admet, et aucune autre suite n'étant modifiée : une suite « (?P< » dans une
classe (`[(?P<]x`) ou après une parenthèse échappée (`a\(?P<b`, `\(?P<x>`)
n'ouvre pas de groupe et garde son sens, alors qu'un remplacement textuel
lui en donnerait un autre que celui de Go ; `\\(?P<x>a)`, barre oblique
inverse échappée suivie d'un vrai groupe nommé, est réécrit. Le même
sous-ensemble, les mêmes règles a) à c) et la même compilation valent pour
`extract` des gabarits d'effets (EX-7.6), contrôlé au démarrage comme les
motifs nommés (EX-15.4 pas 3). Le vecteur `redaction/motifs.json` de
l'annexe B donne des motifs admis et refusés, et, pour certains motifs
admis, la première correspondance de textes donnés (B.3).

#### 10.2.2 Portées

| Portée | Pièce (section 8) | Racine du pointeur | Produite par |
|---|---|---|---|
| `arguments` | « arguments » d'un appel d'outil (`params.arguments`) | l'objet des arguments | frontal MCP (4.4 pas 4), SDK (`debutAppel`) |
| `resultat` | « résultat » d'un appel d'outil (`result` reçu, membres présents) | l'objet `result` | frontal MCP (4.4 pas 12), SDK (`finAppel`) |
| `requete` | « requête » d'un échange de modèle (corps JSON de la requête ; `params` de `sampling/createMessage`) | le corps | frontal modèle (5.3), frontal MCP (EX-4.29), SDK (`echangeModele`) |
| `reponse` | « réponse » d'un échange de modèle (corps JSON hors flux, forme consolidée en flux, `CreateMessageResult`) et, par extension, le texte `intent` qui en est tiré (EX-5.21) | la réponse | idem |
| `prompt_systeme` | « prompt système » (8.2, pièce `text/plain`), texte extrait selon la table de 5.5 | la chaîne | frontal modèle, SDK |
| `contexte` | pièces de contexte remises par le SDK (`declarerContexte`) ; la pièce de définition d'outil (EX-4.16) **n'est pas** rédigée (c'est l'annonce du serveur, prouvée telle quelle) | la valeur ou la chaîne | SDK |

#### 10.2.3 Actions et jetons de remplacement

| `action.kind` | Effet sur une correspondance | Jeton |
|---|---|---|
| `remplacer` (défaut recommandé) | La correspondance est remplacée par le jeton. Pour `champ`, la valeur désignée par `path`, quel que soit son type JSON, est remplacée par la **chaîne** jeton. | `[REDIGE:<type>]` où `<type>` est `iban`, `avs`, `email`, `telephone`, `carte`, le `name` du motif nommé, ou le `label` du détecteur `champ`. Exemple : `[REDIGE:iban]`, celui de CT-1 §5.5. |
| `pseudonyme` | Comme `remplacer`, avec un jeton qui porte un pseudonyme à clé (10.3.9) : la même valeur donne le même jeton tant que la clé ne change pas. | `[PSEUDO:<type>:<12 chiffres hexadécimaux minuscules>]` |
| `supprimer` | Le membre d'objet désigné par `path` est retiré de son objet parent ; si `path` désigne un élément de tableau, l'élément est remplacé par la chaîne `[REDIGE:<label>]` (un retrait décalerait les indices que d'autres règles ou un gabarit d'effets attendent) ; si `path` est vide (racine), la pièce entière devient la chaîne `[REDIGE:<label>]`. | — |

**EX-10.7** Les jetons sont des chaînes ASCII fixes, dans la forme ci-dessus,
sans espace. Le prompt système remplacé dans la pièce « requête » par
`model.prompt_in_request: "reference"` (5.3.1) emploie le jeton
`[REDIGE:prompt-systeme]`, qui n'est pas une rédaction au sens de cette
section (il ne marque pas `redacted: true` à lui seul : la pièce « prompt
système » existe à part et porte sa propre référence).

### 10.3 Détecteurs exacts

#### 10.3.1 Règles communes

**EX-10.8** Un détecteur de texte (`iban`, `avs`, `email`, `telephone`,
`carte`, `regex`) opère sur la chaîne JSON **telle qu'elle est** : suite de
points de code Unicode, sans aucune normalisation (ni NFC, ni NFD, ni NFKC) et
sans changement de casse. Motif : une normalisation changerait les octets de
chaînes qui ne contiennent aucune donnée sensible et rendrait `redacted`
indécidable ; les alphabets des cinq détecteurs nommés sont ASCII ; le
remplacement se fait par substitution de la sous-chaîne correspondante, le
reste de la chaîne est recopié à l'identique. Les formes de compatibilité
(NFKC) « ne doivent pas être appliquées aveuglément à un texte arbitraire »
(UAX #15, R6), et les homoglyphes (UTS #39) ne sont pas traités en version 0
(10.8).

**EX-10.9** Dans une même règle, les détecteurs sont appliqués **l'un après
l'autre, dans l'ordre du tableau `detectors`**, chacun sur la chaîne produite
par le précédent ; à l'intérieur d'un détecteur, les correspondances sont
cherchées de gauche à droite, sans chevauchement, chaque recherche reprenant
immédiatement après la fin de la correspondance précédente (une correspondance
remplacée n'est pas réexaminée par le même détecteur), et **la fin d'une
correspondance remplacée vaut frontière** pour le candidat qui suit (comme le
`]` du jeton qui la remplace). Les règles sont appliquées l'une après l'autre
(10.4). Les positions sont comptées en points de code.

**Jetons opaques.** Un **jeton** est une sous-chaîne de la forme
`[REDIGE:<t>]` ou `[PSEUDO:<t>:<12 chiffres hexadécimaux minuscules>]`, où
`<t>` est l'un des types de jetons de la politique (les cinq détecteurs
nommés, chaque nom de motif nommé et chaque étiquette `champ` employés, et
`prompt-systeme`). Un détecteur de texte opère sur chacun des **segments**
de la chaîne situés entre les jetons, indépendamment, chaque bord de segment
valant début ou fin de chaîne pour les frontières ; il ne trouve jamais de
correspondance qui chevauche un jeton ni qui soit à l'intérieur d'un jeton
(un pseudonyme de douze chiffres décimaux passant Luhn n'est pas une carte).

**Séparateurs admis** dans les candidats numériques : l'espace U+0020, l'espace
insécable U+00A0, l'espace insécable étroite U+202F (notées `SEP`) ; le trait
d'union-signe moins U+002D (`-`) là où un détecteur l'admet ; le point U+002E
(`.`) là où un détecteur l'admet. Un séparateur n'est admis qu'**isolé** (deux
séparateurs consécutifs rompent le candidat) et jamais en tête ni en fin de
candidat.

**Frontières** : sauf mention contraire, un candidat DOIT être précédé du début
de la chaîne ou d'un caractère qui n'est ni un chiffre ASCII ni une lettre
ASCII, et suivi de la fin de la chaîne ou d'un tel caractère. Les tests de
frontière portent sur le point de code adjacent, après les séparateurs
éventuellement avalés par le candidat.

Un candidat qui échoue à sa somme de contrôle n'est **pas** rédigé : la somme
de contrôle est ce qui abaisse les faux positifs, comme chez les trois outils
de référence (« Pattern match and checksum », Presidio ; vraisemblance
`POSSIBLE` « can include passing checksums », Google, R6).

#### 10.3.2 `iban`

Sources : SIX (structure, méthode « modulo 97-10 according to ISO/IEC 7064 »,
longueur CH/LI 21), Pay.UK (génération et exemple), Banque centrale de Turquie
(validation : reste 1, calcul par blocs), autorités nationales pour les
longueurs (R6 § 1.2 ; les textes ISO 13616-1 et ISO/IEC 7064 et le registre
SWIFT n'ont pas pu être lus, R6 § 2).

1. **Candidat.** À une position `p` précédée d'une frontière, la chaîne porte
   deux lettres ASCII majuscules puis deux chiffres : `CC = s[p..p+2)`,
   `KK = s[p+2..p+4)`. Si `CC` n'est pas dans la table ci-dessous, aucun
   candidat à `p`. Soit `L` la longueur de la table. On lit ensuite, à partir
   de `p+4`, des caractères de `[A-Z0-9]`, en admettant entre deux d'entre eux
   un `SEP` isolé, jusqu'à avoir lu exactement `L − 4` caractères
   alphanumériques ; si la chaîne s'épuise avant, ou si un caractère hors
   alphabet et hors `SEP` apparaît avant, aucun candidat. Le caractère qui
   suit le dernier alphanumérique lu DOIT être une frontière ; sinon, aucun
   candidat.
2. **Forme normalisée** `N` : les `L` caractères alphanumériques, sans
   séparateur, tels quels (majuscules).
3. **Somme de contrôle MOD 97-10.** Soit `R` = `N[4..L) ‖ N[0..4)` (les quatre
   premiers caractères déplacés à la fin). Remplacer chaque lettre par deux
   chiffres : `A → 10`, `B → 11`, …, `Z → 35` (valeur = code ASCII − 55) ;
   les chiffres restent. Le nombre décimal obtenu, `D`, est réduit modulo 97
   par blocs : `r ← 0` ; pour chaque bloc `b` de 9 chiffres au plus, pris de
   gauche à droite (le dernier bloc peut être plus court), `r ← (r ‖ b) mod
   97` où `r ‖ b` est la concaténation décimale. Le candidat est valide si et
   seulement si `r = 1`. (Génération, pour mémoire : `98 − (… mod 97)`,
   Pay.UK.)
4. **Correspondance** : du premier caractère de `CC` au dernier alphanumérique
   lu, séparateurs compris. Valeur pour le pseudonyme : `N`.

| Pays | `CC` | `L` | Source (R6) |
|---|---|---|---|
| Suisse, Liechtenstein | `CH`, `LI` | 21 | SIX |
| Allemagne | `DE` | 22 | Deutsche Bundesbank |
| France | `FR` | 27 | CFONB |
| Italie | `IT` | 27 | Banca d'Italia |
| Autriche | `AT` | 20 | oesterreich.gv.at |
| Espagne | `ES` | 24 | Banco de España |
| Pays-Bas | `NL` | 18 | Betaalvereniging Nederland |
| Belgique | `BE` | 16 | Febelfin |
| Royaume-Uni | `GB` | 22 | Pay.UK |
| Luxembourg | `LU` | 20 | ABBL |

Exemples : `CH9300762011623852957` → `R = 00762011623852957CH93` → `D =
00762011623852957121793`, `r = 1` : valide. `CH93 0076 2011 6238 5295 7`
(groupes de quatre) : même `N`, valide. `CH9300762011623852958` : `r = 28`,
invalide, non rédigé. `GB19LOYD30961700709943` (exemple Pay.UK) : valide. Un
IBAN d'un pays hors table (Norvège, Malte, …) n'est pas détecté en version 0
(10.8) ; un IBAN en minuscules non plus.

#### 10.3.3 `avs`

Sources : RAVS art. 133 (treize chiffres : `756`, neuf chiffres, clé ; état
au 1er janvier 2024) ; ordonnance du DFI du 7 novembre 2007 (RS 831.101.4),
annexe 1, pour l'algorithme de la clé, et annexe 1 C pour l'écriture
`756.XXXX.XXXX.XX` (« 756.1234.5678.9? »,
https://www.newsd.admin.ch/newsd/message/attachments/10042.pdf) ; l'OFAS
écrit seulement que le numéro « commence par les chiffres 756 » (R6 § 1.2).
La dénomination « EAN-13 » de l'algorithme n'est pas dans l'ordonnance (R6
§ 2) ; elle n'est pas employée ici.

1. **Candidat.** À une position précédée d'une frontière : `756`, puis un
   séparateur optionnel (`.` ou `SEP`), puis quatre chiffres, puis un
   séparateur optionnel, puis quatre chiffres, puis un séparateur optionnel,
   puis deux chiffres, puis une frontière. Les trois séparateurs sont
   indépendamment présents ou absents, mais s'ils sont présents ils DOIVENT
   être tous du même caractère.
2. **Forme normalisée** `N` : les treize chiffres `x1 … x13`.
3. **Clé de contrôle.** `S = Σ_{i=1}^{12} x_i · w_i` avec `w_i = 1` pour `i`
   impair et `w_i = 3` pour `i` pair (de gauche à droite : 1, 3, 1, 3, …, 1,
   3 ; c'est l'énoncé de l'ordonnance « multiplier alternativement par 3 et
   par 1 chaque chiffre, en commençant par l'avant-dernier », lu de droite à
   gauche). `clé = (10 − (S mod 10)) mod 10`. Le candidat est valide si et
   seulement si `clé = x13`.
4. **Correspondance** : du `7` initial au dernier chiffre. Valeur pour le
   pseudonyme : `N`.

Exemple de l'ordonnance : `756.1234.5678.9?` → `S = 7+15+6+3+2+9+4+15+6+21+8+27
= 123`, `clé = 7` : `756.1234.5678.97` est valide ; `756.1234.5678.90` est
invalide, non rédigé.

#### 10.3.4 `carte`

Sources : brevet US 2,950,048 (Luhn) ; longueur 12 à 19 chiffres attestée
par Google et Presidio (ISO/IEC 7812 non lue, R6 § 2) ; American Express « 34
ou 37, 15 chiffres » (source émetteur) ; aucun préfixe d'autre réseau n'est
sourcé et aucun n'est employé (R6 § 2). Le détecteur ne distingue pas les
réseaux : il reconnaît une suite de chiffres de longueur plausible qui passe
Luhn.

1. **Candidat.** Une suite maximale de caractères de l'alphabet `[0-9]`, `SEP`
   et `-`, commençant et finissant par un chiffre, précédée et suivie d'une
   frontière, dont les séparateurs sont isolés, et qui compte entre 12 et 19
   chiffres. Le point n'est pas admis (il sépare les groupes du numéro AVS et
   les décimales des montants).
2. **Forme normalisée** `N` : les chiffres seuls.
3. **Luhn.** En parcourant `N` de droite à gauche, le chiffre de rang 1 (le
   dernier) est pris tel quel, le rang 2 est doublé, le rang 3 tel quel, et
   ainsi de suite en alternant ; un produit supérieur à 9 est diminué de 9 ;
   la somme de tous les termes est `S`. Le candidat est valide si et
   seulement si `S mod 10 = 0`.
4. **Correspondance** : la suite entière, séparateurs compris. Valeur pour le
   pseudonyme : `N`.

Exemples : `378282246310005` (15 chiffres, commence par `37`) : valide ;
`3782 822463 10005` : même `N`, valide ; `378282246310006` : invalide. Un
numéro écrit avec des points, ou porté par un nombre JSON, n'est pas détecté
(10.8).

#### 10.3.5 `email`

Sources : RFC 5321 § 4.1.2 (`Mailbox = Local-part "@" ( Domain /
address-literal )`), § 4.5.3.1.1 (partie locale ≤ 64 octets), § 4.5.3.1.2
(domaine ≤ 255 octets) ; RFC 5322 § 3.2.3 (`atext`) (R6 § 1.2). La version 0
retient la forme pratique « `Dot-string @ Domain` » et laisse de côté les
formes `Quoted-string`, `address-literal` et les formes obsolètes de la
RFC 5322 (10.8), comme le recommande le digest.

La recherche part de chaque `@` et lit au plus 64 caractères à sa gauche et
256 à sa droite, les bornes mêmes de la RFC 5321 : son coût est linéaire en
la longueur de la chaîne, quel que soit le moteur (une recherche par
expression régulière qui, après un rejet, reprend « un caractère plus loin »
est quadratique : environ 2 s pour 64 000 caractères et 5 à 10 s pour
128 000 sous Node 22, mesure de la revue de sécurité).

1. **Candidat.** Pour chaque `@` de la chaîne (de gauche à droite, hors des
   correspondances déjà trouvées) :
   - la partie locale `L` est la suite maximale, immédiatement à gauche du
     `@`, de caractères de `[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]`, sans dépasser
     vers la gauche le début de la chaîne (ou du segment, EX-10.9) ni la fin
     de la correspondance précédente de ce détecteur ; la lecture vers la
     gauche s'arrête au 65e caractère : si `L` en compte plus de 64, aucun
     candidat à ce `@` ; `L` DOIT être une `Dot-string` (non vide, ni `.`
     initial, ni `.` final, ni `..`) ;
   - le domaine `D` est la suite maximale, immédiatement à droite du `@`, de
     caractères de `[A-Za-z0-9.-]`, lue sur 256 caractères au plus : si elle
     en compte plus de 255, aucun candidat ; si `D` se termine par un `.` ou
     un `-`, ce dernier caractère n'en fait pas partie (le point final d'une
     phrase : `… j.dupont@example.ch.`) ; `D` DOIT alors être formé d'au
     moins deux labels séparés par `.`, chacun de 1 à 63 caractères de
     `[A-Za-z0-9-]` ne commençant ni ne finissant par `-`, le dernier fait
     d'au moins deux lettres ASCII.
2. **Correspondance** : `L @ D`. Par la maximalité de `L` et de `D`, le
   caractère qui la précède n'est pas dans l'alphabet de `L`, et celui qui la
   suit n'est pas dans `[A-Za-z0-9]` (c'est au plus le `.` ou le `-` retiré
   de `D`). Les deux parties ne contiennent que de l'ASCII : 64 caractères
   sont 64 octets (RFC 5321 § 4.5.3.1.1, § 4.5.3.1.2). Valeur pour le
   pseudonyme : partie locale telle quelle, `@`, domaine en minuscules ASCII
   (la partie locale « MAY be case-sensitive », RFC 5321).

Exemples : `j.dupont@example.ch` → `[REDIGE:email]` ; `Écrire à
j.dupont@example.ch.` → `Écrire à [REDIGE:email].` ; `a..b@example.ch` et
`x@example` ne sont pas rédigés.

#### 10.3.6 `telephone`

Source : UIT-T E.164 (02/2026) : au plus 15 chiffres hors préfixe
international, indicatif de pays de un à trois chiffres, le signe `+`
n'appartient pas au numéro (R6 § 1.2). La version 0 ne détecte que la forme
internationale introduite par `+` ; une forme nationale sans `+` n'est pas
détectée (10.8). La longueur minimale, 8 chiffres, est un choix de cette
spécification (aucune borne basse lue), pour écarter des suites courtes
(« +41 44 » seul).

1. **Candidat.** À une position `p` où la chaîne porte un `+` précédé d'une
   frontière (ou du début, ou de la fin de la correspondance précédente,
   EX-10.9) et suivi d'un chiffre `1` à `9`, on parcourt la chaîne à partir
   de `p + 1` en tenant `fin`, la position qui suit le dernier chiffre
   retenu :
   - un chiffre est lu et `fin` passe derrière lui ;
   - un séparateur (`SEP`, `-`, `.`) est lu si le caractère qui le précède
     n'est pas un séparateur ; sinon le parcours s'arrête ;
   - une `(` : si un groupe a déjà été lu, le parcours s'arrête ; sinon, si
     elle est suivie d'au moins un chiffre puis d'une `)`, le groupe entier
     `(chiffres)` est lu, **sans** déplacer `fin` ; sinon le parcours
     s'arrête ;
   - tout autre caractère arrête le parcours.

   Le candidat va de `p` à `fin` (exclu) : il finit toujours par un chiffre,
   et un groupe entre parenthèses n'en fait partie que si un chiffre le suit
   (`+41 (0)44 123 45 67`). C'est le plus long préfixe qui respecte les
   contraintes : une `(` non refermée sur des chiffres, ou un groupe que rien
   ne suit, termine le candidat avant la `(`. Le caractère à `fin` DOIT être
   une frontière, sinon aucun candidat à `p` (aucun préfixe plus court n'est
   essayé). Le nombre de chiffres du candidat, groupe compris, est entre 8 et
   15.
2. **Forme normalisée** `N` : `+` suivi des chiffres seuls.
3. **Correspondance** : du `+` au dernier chiffre. Valeur pour le pseudonyme :
   `N`.

Exemples : `+41 44 123 45 67` → `N = +41441234567` → `[REDIGE:telephone]` ;
`+41 44 123 45 67 (9h-17h)` → `[REDIGE:telephone] (9h-17h)` ;
`+33 1 23 45 67 89 (2)` → `[REDIGE:telephone] (2)`.

#### 10.3.7 `regex` (motif nommé)

**EX-10.10** Un détecteur `{ "type": "regex", "name": n }` applique le motif
`named_patterns[n].pattern` (RE2, leftmost-first, sans drapeau) à la chaîne,
correspondance par correspondance sans chevauchement ; chaque correspondance
non vide est remplacée par `[REDIGE:n]` ou `[PSEUDO:n:…]`. Une correspondance
vide est ignorée (et la recherche avance d'un point de code). Aucune frontière
implicite n'est ajoutée : le motif les porte s'il le veut (`\b`). Valeur pour
le pseudonyme : la correspondance telle quelle.

#### 10.3.8 `champ`

**EX-10.11** Un détecteur `{ "type": "champ", "label": l }`, toujours avec
`path`, porte sur **la valeur désignée**, quel que soit son type : avec
`remplacer`, elle devient la chaîne `[REDIGE:l]` ; avec `pseudonyme`, la chaîne
`[PSEUDO:l:…]` calculée sur la chaîne elle-même si la valeur est une chaîne
(comme un détecteur de texte, de sorte qu'une même chaîne donne le même jeton
par `champ` et par un détecteur de même type), sur son JCS intégral sinon ;
avec `supprimer`, 10.2.3. Une valeur qui est **déjà un jeton** (EX-10.9),
quel qu'en soit le type, est laissée telle quelle. C'est le détecteur à
employer quand le client sait où est la donnée (un champ `beneficiary_iban`,
un champ `patient`) et ne veut pas dépendre d'une heuristique.

#### 10.3.9 Action `pseudonyme`

**EX-10.12** Le pseudonyme d'une valeur normalisée `V` (chaîne UTF-8) pour un
type `t` est :

```text
P = HMAC-SHA-256( K, UTF-8(t) ‖ 0x00 ‖ UTF-8(V) )
jeton = "[PSEUDO:" ‖ t ‖ ":" ‖ hex_minuscule(P[0..6)) ‖ "]"      (12 chiffres hexadécimaux, 48 bits)
```

où `K` est la suite d'octets obtenue en décodant la valeur du secret
`pseudonym_key` selon l'`encoding` de sa référence (15.2 : `hex`, avec ou sans
préfixe `0x`, longueur paire ; `base64`, alphabet de la RFC 4648 § 4 avec
remplissage ; `utf8`, les octets UTF-8 de la chaîne), **au moins 32 octets
après décodage**, tirés au hasard ; jamais dérivés d'une date ou d'un nom :
« the secrets should have sufficient entropy », CEPD 01/2025 § 88, note 24,
R6), résolue au démarrage et tenue hors du journal. Une clé produite par
`openssl rand -hex 32` se déclare `"encoding": "hex"` : deux implémentations
obtiennent les mêmes 32 octets et les mêmes pseudonymes.

**EX-10.13** L'action `pseudonyme` est une **option explicite** du client,
avec son risque, écrit ici et dans la documentation : (1) la même valeur
donne le même jeton dans tout le journal tant que `K` ne change pas — c'est
l'intégrité référentielle recherchée, et c'est aussi ce qui permet de relier
tous les événements qui concernent une même personne ; (2) qui détient `K`
recalcule le pseudonyme de toute valeur devinée ; une fuite de `K` rend le
journal recoupable par dictionnaire ; (3) le journal pseudonymisé reste une
donnée personnelle (RGPD, considérant 26 ; CEPD 01/2025 : « Pseudonymised
data […] is to be considered information on an identifiable natural person »,
R6) ; (4) la rotation de `K` (nouveau secret, nouveau `name` de politique)
rompt l'intégrité référentielle entre l'avant et l'après, ce qui est voulu,
et doit être planifiée ; le CEPD demande un plan de remplacement des
algorithmes et paramètres devenus faibles (« the controllers need to draw up
a plan for replacement of weak algorithms should it become necessary »,
01/2025 § 91,
https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf).
Les 48 bits du jeton bornent la
recherche par le journal seul, pas celle par dictionnaire avec `K`.

### 10.4 Ordre d'application, idempotence, marquage

**EX-10.14** Pour une pièce de portée `S`, rattachée à l'outil annoncé `T`
(ou sans outil), le rédacteur parcourt `rules` dans l'ordre et retient chaque
règle dont `scopes` contient `S` et dont `tools` vaut `"*"`, contient `T`, ou
contient `<alias>__*` avec l'alias de `T`. Chaque règle retenue est appliquée
à la valeur produite par la précédente :

1. résolution de `path` (ou racine) ; échec → règle sans effet, note ;
2. parcours de la valeur désignée en **profondeur d'abord**, membres d'objet
   dans l'ordre des unités de code UTF-16 de leurs noms (l'ordre de JCS, CT-1
   §4), éléments de tableau dans l'ordre ; chaque chaîne rencontrée est
   soumise aux détecteurs de texte de la règle, dans l'ordre (EX-10.9) ; le
   détecteur `champ` et l'action `supprimer` opèrent sur la valeur désignée
   elle-même (10.3.8, 10.2.3) ;
3. la chaîne ou la valeur modifiée remplace l'originale dans la structure.

L'application de toutes les règles retenues forme un **passage**. Le
rédacteur DOIT refaire un passage tant que le précédent a modifié la valeur :
une règle peut en effet créer, en rédigeant, la frontière qui manquait au
candidat d'une règle ou d'un détecteur déjà appliqués (`CH93…957+41441234567`
avec les détecteurs `telephone` puis `iban` : le téléphone n'est rédigé qu'au
second passage, une fois l'IBAN remplacé par son jeton). Chaque passage qui
modifie la valeur remplace des caractères hors jeton par un jeton, remplace
une valeur qui n'est pas un jeton par un jeton, ou retire un membre ; les
jetons n'étant jamais modifiés (EX-10.9, EX-10.11), le nombre de passages
est fini (en pratique un, plus le passage qui constate l'absence de
changement). Les compteurs d'EX-10.17 additionnent les passages.

**EX-10.15** La politique est **idempotente** : appliquer deux fois la même
politique à la même pièce donne les mêmes octets. Ce n'est pas une
conséquence de la forme des détecteurs (une chaîne rédigée change le
contexte de ses voisines : un `]` de jeton est une frontière là où il y
avait un chiffre) : c'est la règle des passages d'EX-10.14 qui la garantit,
puisque la valeur produite est celle sur laquelle un passage ne change plus
rien, avec l'opacité des jetons (EX-10.9) et l'invariance de `champ` sur un
jeton (EX-10.11). Un lecteur peut donc réappliquer la politique à une pièce
stockée pour vérifier qu'elle est bien rédigée (égalité des octets), ce qui
est un test de CT-9.

**EX-10.16** La référence porte `redacted: true` si et seulement si les octets
de la pièce stockée (JCS intégral de la valeur après application des règles)
diffèrent des octets qu'aurait donnés la valeur avant application (JCS
intégral de la valeur d'origine) ; `false` sinon, y compris quand des règles
étaient applicables mais qu'aucun détecteur n'a correspondu. Le noyau calcule
donc les deux sérialisations et compare, sans stocker la première. Quand une
pièce d'un événement porte `redacted: true`, `policy.redaction` reçoit `name`
(CT-1 E-4) ; sinon `null` (CT-1 §5.3). Le remplacement du prompt système par
`[REDIGE:prompt-systeme]` dans la pièce « requête » (EX-10.7) rend la pièce
« requête » différente du corps reçu : il **compte** comme une rédaction pour
`redacted` et `policy.redaction` (c'est ainsi que l'événement seq 1 de CT-1
annexe A porte `redacted: true` et `redaction: "pii-v1"` sur sa requête).

**EX-10.17** Le journal d'exploitation reçoit, par pièce rédigée, un
enregistrement `redaction_applied` avec le `seq` de l'événement (ou l'`id`
de l'appel avant scellement), la portée, l'`id` de chaque règle qui a
modifié la pièce et, par détecteur, le **nombre** de correspondances et leur
type ; jamais les valeurs, jamais leur position (une position révèle la
longueur). Les métriques comptent les correspondances par type (section 17).

**EX-10.18** `intent` tiré d'une réponse de modèle n'est **pas** rédigé à
part : il est extrait de la valeur déjà rédigée de la pièce « réponse »
(EX-5.21, EX-5.22), de sorte qu'une règle à `path` de portée `reponse`
(`/content/0/text` avec `champ`, par exemple) le couvre comme elle couvre la
pièce ; le texte extrait n'est jamais tiré de la réponse en clair, et sa
référence porte `redacted: true` quand il diffère du texte que la réponse en
clair aurait donné. Le texte d'une pièce `text/plain` d'une autre origine
(contexte SDK, `intent` déclaré par le SDK) a pour racine la chaîne entière,
à laquelle s'appliquent les règles de la portée (`contexte`, `arguments`)
selon EX-10.14, `path` compris : sur une racine chaîne, seul le pointeur
vide résout (10.2.1), et une règle dont `path` n'est pas vide n'a pas d'effet
sur la pièce ; la référence porte `redacted` selon EX-10.16. Une valeur en
ligne (EX-6.6, EX-7.2, EX-8.6, EX-10.24) n'est pas une pièce : le `path` des
règles n'y est pas résolu, la chaîne est la racine.

**EX-10.23** **Coût borné.** Les détecteurs nommés DOIVENT être implémentés
en temps linéaire en la longueur de la chaîne (10.3 : lectures bornées, aucun
retour arrière non borné). Les motifs (motifs nommés et `extract`) sont
exécutés sous une **borne de temps** : `limits.redaction_budget_ms`, un
entier d'au moins 1 (1 000 dans la configuration de référence ; le schéma
refuse 0), mesuré sur une horloge monotone depuis le début de l'opération,
pour chacune des opérations suivantes :

1. la rédaction d'une pièce, tous passages et toutes règles compris
   (EX-10.14) : au-delà, la pièce est remplacée par la pièce « non
   rédigeable » d'EX-8.7 (`reason: "budget_redaction"`, `content_type` du
   corps ou `null`, `length` d'EX-8.7), `redacted: true`, et la copie
   partiellement rédigée est jetée ; pour la pièce « arguments » d'un outil
   de classe `ecriture` ou susceptible d'approbation dont la réponse
   d'`evaluer` mène à un relais ou à un événement `retenue`, l'appel est en
   outre refusé avant tout relais (4.4 pas 4, `debutAppel`) : `-31010`,
   raison `redaction`, ni intention ni événement, consigné
   (`redaction_budget_exceeded`, opération `piece`, portée `arguments`) et
   compté dans `noortrace_calls_blocked_total` ; un ticket `nouveau` que le
   service a réservé reste `reserve` et devient `abandonne` (CT-3 T3), une
   approbation servie ne se libère pas (CT-3 EX-7.17). La taille ou la forme
   des données suffit en effet à dépasser la borne, même sans motif nommé :
   sous `pii-v1`, des arguments de quelques mégaoctets la dépassent selon la
   machine et la charge (EX-10.4), et un appel d'écriture relayé avec une
   pièce vide effacerait de la preuve ce qu'il écrit ;
2. l'évaluation d'un gabarit d'effets (EX-7.6, pas 3) : au-delà, l'effet est
   omis avec la note `effect_omitted`, raison `budget_redaction` ; pour un
   outil de classe `ecriture`, si aucun effet n'est produit parce qu'un
   `extract` a dépassé la borne ou parce qu'une pièce source (« arguments »
   ou « résultat ») est la pièce non rédigeable, l'effet par défaut d'EX-7.6
   (2) est déclaré à la place ;
3. l'examen d'une valeur en ligne par les détecteurs (`run_id` et nom de
   prompt déclarés, EX-7.2, EX-8.6 ; chaînes des effets déclarés par le SDK,
   EX-6.6 ; motif d'une décision, EX-10.24) : au-delà, la valeur est traitée
   comme une valeur dans laquelle un détecteur a trouvé une correspondance
   (valeur déclarée refusée, effet omis), et le motif d'une décision devient
   `null` ;
4. le contrôle, au démarrage, au rechargement et par la commande de
   validation (EX-15.4 pas 3), qu'aucun motif nommé ne fait correspondre un
   jeton de la politique (EX-10.6), motif par motif : au-delà, le motif est
   refusé (« motif trop coûteux sur les jetons ») et la configuration avec
   lui ; un motif admis par EX-10.6 peut en effet mettre des secondes sur ces
   seuls jetons, et bloquer le démarrage ou le rechargement : `[^x]*` répété
   huit fois puis `x` y met 5 161 ms sans borne, contre 178 ms répété six fois
   (mesure sous Node.js v22.22.0, le 2026-10-23, avec
   `scripts/lib/capture.mjs`).

L'implémentation DOIT pouvoir interrompre l'opération au dépassement, même
au milieu d'une correspondance : un moteur à retour arrière (ECMAScript) ne
rend pas la main de lui-même, et les règles d'EX-10.6 n'excluent pas le
retour arrière polynomial (R10 F-27). Avec Node.js, une exécution dans un
contexte `node:vm` avec l'option `timeout` interrompt une recherche en cours,
y compris dans une fonction du contexte principal appelée depuis ce
contexte, pour un surcoût mesuré d'environ 0,16 ms par appel ; l'arrêt d'un
`Worker` par `terminate()` prend de 2 à 3 ms (R10 F-36). `replace`,
`replaceAll`, `split`, `matchAll`, `match`, `search` et `test` sont
interrompus de même : sous Node.js v22.22.0, avec une borne de 50 ms et
`[0-9]+$` sur 80 000 chiffres suivis de `x`, chaque méthode s'arrête entre
49,5 et 50,8 ms, quand `exec` et `replace` sans borne durent 4 365 et
4 888 ms ; le surcoût mesuré est de 0,14 ms par appel (mesure du
2026-10-23 avec `scripts/lib/capture.mjs`, et test/enregistreur.test.js,
qui borne la durée par la borne plus 450 ms : R10 NV-4 levé). Cette
exécution est synchrone : elle occupe le fil qui l'appelle jusqu'à la
borne, d'où EX-3.6. Le moteur à temps linéaire
de V8 n'est pas une solution : il est expérimental, derrière une option de
ligne de commande, et refuse le drapeau `u` (R10 F-33, F-34), sans lequel
les correspondances diffèrent de celles de Go (R10 F-35). Un moteur à temps
linéaire (paquet `regexp` de Go) applique la même borne, son coût croissant
avec la taille du motif (R10 F-29). Chaque dépassement est consigné
(`redaction_budget_exceeded`, opération, portée, règle, sans valeur) et
compté (17.2) ; hors du refus de l'opération 1 et du refus de configuration
de l'opération 4, l'appel suit son cours : la preuve perd le contenu de la
pièce ou de la valeur (une lecture, ou le résultat d'une écriture déjà
exécutée), jamais le journal ne reçoit le clair. Un dépassement
dépend de la machine (EX-10.4) : aucun vecteur de l'annexe B n'est près de
la borne ; le cas `email-long` est un cas de longueur, sans assertion de
durée, et un test de dépassement emploie une borne très petite ou une
entrée très au-delà de la borne.

**EX-10.24** **Motif d'une décision.** Avant de sceller une décision
`approuve` ou `refuse` (EX-7.19), le noyau DOIT appliquer à
`approval.reason`, s'il n'est pas `null`, pris comme une pièce texte (la
chaîne est la racine), les règles de la politique de rédaction en vigueur
dont les détecteurs sont des détecteurs de texte (`iban`, `avs`, `carte`,
`email`, `telephone`, `regex`), quels que soient leur portée, leurs outils
et leur `path` (la chaîne du motif est la racine et le pas 1 d'EX-10.14 ne
s'applique pas : une règle dont le `path` vise `/beneficiary_iban` rédige
aussi l'IBAN qu'un approbateur écrit dans le motif), avec leur action
(`remplacer` ou `pseudonyme`), dans l'ordre et par passages comme EX-10.14 ;
les détecteurs `champ` et l'action `supprimer` ne s'y appliquent pas. Un
motif rédigé de plus de 1 024 caractères (un jeton peut allonger le texte)
est tronqué à ses 1 024 premiers points de code
(CT-1 §5.3). Le motif rédigé est celui de l'`approval` scellé et rendu au
service par `acquitter` (CT-3 EX-9.14, EX-12.9). Les chaînes fixes d'une
décision `expire` (CT-3 EX-7.11, EX-9.4) ne sont pas rédigées. `reason`
n'est pas signé par les approbateurs (CT-1 §6.3) : le rédiger n'invalide
aucune signature. Le motif est une valeur en ligne, dans la chaîne, qui ne
peut pas être purgée (EX-10.2) : la console avertit déjà qu'il ne doit
contenir aucune donnée personnelle (CT-3 EX-9.14), et la rédaction est la
seconde barrière, que CT-3 demande au noyau (DEVRAIT) et que CT-2 rend
obligatoire.

### 10.5 Prompt système

**EX-10.19** Le prompt système est une pièce comme les autres (CT-1 §5.3 et
§15) : la portée `prompt_systeme` s'y applique avant hachage, et
`code.prompt_version` est le SHA-256 de la pièce **rédigée** (8.2, EX-8.6).
Un prompt système qui ne contient aucune donnée détectée est stocké en clair
chez le client, et son empreinte circule dans tout dossier : c'est le risque
énoncé en CT-1 §15 (confirmation d'un prompt deviné par dictionnaire), que le
client traite soit par une règle `champ` sur la portée `prompt_systeme`
(pointeur `""`, action `remplacer`, étiquette `prompt-systeme` : la pièce
devient le jeton, `prompt_version` devient l'empreinte du jeton, constante,
et perd son rôle d'identifiant de version), soit par un motif nommé qui
rédige les seules parties sensibles, soit par l'identifiant de version nommé
d'EX-8.6 (`model.prompt_system: "named"`, pièce `[PROMPT:<nom>]`, qui ne
prouve plus le contenu du prompt), soit en acceptant le risque pour un prompt
sans donnée personnelle.

### 10.6 Nommage et hachage : `policy.redaction` et l'ensemble de politique

**EX-10.20** `policy.redaction` d'un événement vaut `name` du document de
rédaction en vigueur à l'instant de la construction, si une pièce de
l'événement a `redacted: true`, et `null` sinon.

**EX-10.21** L'**ensemble de politique** est le membre `policy` du document de
configuration (section 15) : `{ "version", "approval" (règles de CT-3, mode
d'attente, délais), "redaction" (le document de cette section), "servers"
(carte des serveurs d'outils : transports, classes, délais, gabarits
d'effets), "model" (routes du frontal modèle et leurs listes `passthrough`,
EX-5.2), "failure" (réglages de panne, section 14) }`. `code.policy_version
= policy.version`. Tout changement de l'un quelconque de ses membres,
appliqué par rechargement (15.5), produit un événement
`noortrace.journal.politique` dont la référence en ligne est
`{ "policy_version": policy.version, "policy_sha256": SHA-256( JCS_integral(
policy ) ) }`, où `JCS_integral(policy)` est la sérialisation en JCS intégral
(section 8, RFC 8785) du membre `policy` tel qu'il est écrit dans le document
de configuration, références de secrets comprises (ce sont des emplacements,
pas des valeurs), avant toute résolution ; ces mêmes octets sont stockés
comme pièce « document d'ensemble de politique » sous ce `sha256` (8.2,
EX-8.11), pour que le dossier d'un événement de politique puisse l'emporter.
Le changement DOIT s'accompagner
d'une nouvelle valeur de `policy.version` ; un rechargement qui change le
membre sans changer `version` est refusé (15.5). Un changement de `redaction`
DOIT changer `redaction.name` en plus de `policy.version`.

Pour l'exemple de configuration de la section 15.3, `JCS_integral(policy)`
fait 6126 octets et `policy_sha256 =
0xa75af9f5870779f14be7fc8f285a62287660097d6b6377153181a352d69f8912` ; la
valeur en ligne de l'événement de politique est alors
`{"policy_sha256":"0xa75af9f5870779f14be7fc8f285a62287660097d6b6377153181a352d69f8912","policy_version":"2026-11-01"}`
(116 octets, `sha256` de la référence :
`0x77d3368adad6a5a62421901ee91ec7c500950a2c8038a7d58d0450b3665c253e`). La
version 0.3 a changé ces valeurs (4 482 octets et `0xd87b…c811` en version
0.2) en remplaçant le tableau illustratif de `policy.approval.rules` par un
document `politique-approbation-v0`, `mode: "retenir"` par `"erreur"`, et en
donnant au demandeur `poste-cursor` une entrée de `separation.identities`. Le
document `pii-v1` seul (10.9) fait 1462 octets en JCS intégral et a pour
SHA-256 `0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e` ;
cette empreinte n'entre pas dans l'événement (seule celle de l'ensemble y
entre), elle sert au vecteur `redaction` de l'annexe B.

### 10.7 Coffre optionnel des originaux

**EX-10.22** Les originaux non rédigés ne sont jamais stockés par
l'enregistreur en version 0, sauf si `storage.vault.enabled` est vrai. Le
coffre est alors un répertoire distinct du stockage du journal
(`storage.vault.path`, hors du répertoire des segments et des pièces, jamais
dans un dossier de preuve), où chaque pièce rédigée a un homologue chiffré par
**AES-256-GCM** avec une clé propre au coffre (`storage.vault.key`, référence de
secret, 32 octets), nonce de 12 octets aléatoire par fichier, données
associées = le `sha256` de la pièce rédigée (ce qui lie l'original à la
référence du journal), nom de fichier = `sha256` de la pièce rédigée. Le coffre
est **hors chaîne** : rien dans l'événement ne le référence ; son existence est
consignée dans le journal d'exploitation ; sa clé n'est jamais celle du
signataire ; son accès est un acte d'exploitation du client (CT-7, CT-8). Le
coffre existe pour les clients dont une obligation légale ou contractuelle
exige de pouvoir produire l'original ; il déplace le risque, il ne le
supprime pas.

### 10.8 Limites

- **La détection en texte libre est heuristique.** Aucun des trois outils de
  référence ne publie de taux d'erreur ; Presidio écrit « No de-identification
  system is perfect » et « there is no guarantee that Presidio will find all
  sensitive information » (R6). Les cinq détecteurs nommés ne trouvent que ce
  qu'ils décrivent : IBAN des onze pays de la table, en majuscules ; numéro AVS
  à treize chiffres en groupes 3-4-4-2 ; numéro de carte de 12 à 19 chiffres
  passant Luhn, sans point ; adresse en forme `Dot-string@Domain` ; numéro
  international commençant par `+`. Ne sont pas détectés en version 0 : IBAN
  hors table ou en minuscules, numéros nationaux sans `+`, cartes écrites avec
  des points, chiffres de pleine chasse ou homoglyphes (UTS #39), données
  encodées (base64, pourcent, R6 § 1.5), noms de personnes, adresses postales,
  dates de naissance, NIR français, Steuer-ID allemande, codice fiscale
  italien (formats lus mais sommes de contrôle non sourcées, R6 § 2) ; un
  client qui en a besoin ajoute un motif nommé ou une règle `champ`.
- **Rédaction n'est pas anonymisation.** Une pièce rédigée peut rester
  identifiante par son contexte (un montant, une date, un numéro de dossier) ;
  un pseudonyme est une donnée personnelle ; le journal entier est une donnée
  personnelle au sens du RGPD art. 4(1) et de la LPD art. 5 let. a (R6). La
  minimisation (RGPD art. 5(1)(c), LPD art. 6 al. 3 et 4) relève de la
  politique du client et de la rétention (section 12.7), pas de la seule
  rédaction.
- **La rédaction est faite à l'enregistreur, pas chez le fournisseur ni chez
  le serveur d'outils** : la donnée en clair a circulé vers eux ; la rédaction
  protège le journal, pas le trafic.
- **Les nombres JSON** ne sont pas examinés (EX-10.5).
- **La réponse de l'hôte à une elicitation** et les `inputResponses` d'une
  ré-émission MRTR ne sont pas des pièces (EX-4.21) : elles ne sont ni rédigées
  ni journalisées en clair.
- **Deux implémentations** concordent sur un motif nommé parce que la
  validation n'admet que le sous-ensemble commun d'EX-10.6 et ses règles de
  structure et de taille ; les vecteurs de l'annexe B couvrent les cinq
  détecteurs nommés, un motif nommé simple et la liste des constructions
  admises et refusées.
- **Le coût** de la rédaction est borné (EX-10.23) ; au-delà, la pièce perd
  son contenu plutôt que d'exposer le clair. Un motif admis peut encore
  coûter un temps polynomial en ECMAScript : la borne le coupe, la
  validation ne l'empêche pas. Un moteur de correspondance à temps linéaire
  écrit pour l'implémentation de référence n'est pas dans la version 0.3 :
  son équivalence avec Go (sémantique « leftmost-first », groupes de
  `extract`) et son coût restent à établir (R10 NV-5), et il ne dispenserait
  pas de la borne (R10 F-29).

### 10.9 Politique « pii-v1 », publiée

Le document complet, qui valide contre
`spec/schemas/politique-redaction-v0.schema.json` (vérifié avec `ajv-cli` 5,
`--spec=draft2020`, mode strict) et qui est celui de l'exemple de
configuration de la section 15.3 et du vecteur `redaction` de l'annexe B :

<!-- schema: politique-redaction -->
```json
{
  "version": 0,
  "name": "pii-v1",
  "description": "Politique de redaction publiee avec CT-2 : identifiants personnels et financiers courants (IBAN, numero AVS, adresse electronique, numero de telephone international, numero de carte de paiement) remplaces par un jeton type dans toutes les pieces.",
  "pseudonym_key": null,
  "named_patterns": {
    "numero-sinistre": {
      "pattern": "\\b20[0-9]{2}-[0-9]{5}\\b",
      "description": "Numero de dossier de sinistre AAAA-NNNNN de l'assureur de demonstration ; n'est pas une donnee personnelle, declare ici pour montrer une regex nommee et laisse hors de toute regle."
    }
  },
  "rules": [
    {
      "id": "identifiants-arguments-resultat",
      "description": "Arguments et resultats de tout appel d'outil : tout texte.",
      "scopes": ["arguments", "resultat"],
      "tools": "*",
      "detectors": [
        { "type": "iban" },
        { "type": "avs" },
        { "type": "carte" },
        { "type": "email" },
        { "type": "telephone" }
      ],
      "action": { "kind": "remplacer" }
    },
    {
      "id": "identifiants-modele",
      "description": "Requetes, reponses et prompt systeme des echanges de modele : tout texte.",
      "scopes": ["requete", "reponse", "prompt_systeme"],
      "tools": "*",
      "detectors": [
        { "type": "iban" },
        { "type": "avs" },
        { "type": "carte" },
        { "type": "email" },
        { "type": "telephone" }
      ],
      "action": { "kind": "remplacer" }
    },
    {
      "id": "identifiants-contexte",
      "description": "Documents de contexte remis par le SDK : tout texte.",
      "scopes": ["contexte"],
      "tools": "*",
      "detectors": [
        { "type": "iban" },
        { "type": "avs" },
        { "type": "carte" },
        { "type": "email" },
        { "type": "telephone" }
      ],
      "action": { "kind": "remplacer" }
    }
  ]
}
```

L'ordre des détecteurs (IBAN, AVS, carte, adresse, téléphone) est celui qui
évite les captures croisées : un IBAN est consommé avant que `carte` ne voie
ses chiffres ; `avs` exige le préfixe `756` et des points ou espaces que
`carte` n'admet pas ; `telephone` exige le `+`.

Application à l'exemple de référence de CT-1 §5.5 (portée `arguments`, outil
`sap.payments.create`, règle `identifiants-arguments-resultat`, détecteur
`iban`) :

| | Octets (UTF-8, une ligne) | `length` | `sha256` |
|---|---|---|---|
| Valeur reçue (JCS intégral, jamais stockée) | `{"amount":"7400.00","beneficiary_iban":"CH9300762011623852957","claim_id":"2026-77812","currency":"CHF"}` | 104 | non calculé par l'enregistreur |
| Pièce stockée (`redacted: true`) | `{"amount":"7400.00","beneficiary_iban":"[REDIGE:iban]","claim_id":"2026-77812","currency":"CHF"}` | 96 | `0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4` |

(CT-1 §5.5 imprime la même pièce dans l'ordre des clés du fichier d'origine,
`0x0fb2…aaf9` ; la sérialisation canonique de la pièce est fixée par la
section 8 de la présente spécification, et c'est elle que l'annexe A emploie.)

Application à un résultat en texte libre (portée `resultat`, cinq détecteurs,
cinq correspondances) :

| | Octets | `length` | `sha256` |
|---|---|---|---|
| Valeur reçue | `{"note":"Virement au bénéficiaire CH93 0076 2011 6238 5295 7, assuré 756.1234.5678.97, joignable au +41 44 123 45 67 ou j.dupont@example.ch ; carte 3782 822463 10005."}` | 171 | — |
| Pièce stockée | `{"note":"Virement au bénéficiaire [REDIGE:iban], assuré [REDIGE:avs], joignable au [REDIGE:telephone] ou [REDIGE:email] ; carte [REDIGE:carte]."}` | 148 | `0x89a34ad286014dee1e1030caf6d50d32327a77da216dfb4a19154f15b73d5f8e` |

Avec l'action `pseudonyme` et la clé de test des vecteurs `K =
SHA-256(UTF-8("noortrace/vecteurs/v0/cle-pseudonyme/test")) =
0x139011dc372b3ce979a162b0dee18753e67e1477ea4db3c55f929829c2ca3808` (clé
publique et jetable, annexe B), les mêmes valeurs donnent
`[PSEUDO:iban:50d46ea9a82b]` pour `CH9300762011623852957` et
`[PSEUDO:email:b8ac789204a6]` pour `j.dupont@example.ch`.

## 11. Clés de l'enregistreur

Cette section clôt la décision ouverte 2 de l'architecture (« gestion des clés
de l'enregistreur chez le client : HSM, KMS ou TPM, choix par client selon ce
qu'il possède déjà », section 20). Tout ce qui est dit d'un produit vient du
digest R3 (pages officielles des fournisseurs, spécifications OASIS PKCS#11
3.0 et 3.1, RFC 9684, dépôts officiels, relus le 2026-10-22) ; ce que le
digest n'établit pas est marqué « non vérifié ».

### 11.1 Exigences

**EX-11.1** La clé de l'enregistreur est une clé **Ed25519** (RFC 8032), et la
signature est celle de CT-1 §6.2 : Ed25519 pur (ni Ed25519ph, ni Ed25519ctx),
sur le message `P_S ‖ JCS_v0(E')`, signature de 64 octets `R ‖ S`, vérifiée
sans cofacteur. Un backend qui ne sait produire que Ed25519ph, ou qui
pré-hache le message de son propre chef (AWS KMS avec `ED25519_PH_SHA_512` :
« the input is hashed twice: once by you and once by KMS »,
https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html,
R3 F-3), NE DOIT PAS être employé pour cette clé.

**EX-11.2** La clé privée ne réside jamais dans le processus de l'agent ni dans
celui de l'hôte (EX-3.2) ; elle réside dans le signataire : un module
matériel, un service de signature, ou la mémoire du démon de l'enregistreur
(classes C et D). Le connecteur stdio et le SDK n'ont aucun accès au
signataire.

**EX-11.3** Le signataire ne signe que pour l'écrivain qui détient le bail du
journal (section 13) : le démon n'appelle le signataire qu'après avoir vérifié
son bail (EX-13.6), et un backend partagé entre plusieurs instances (service
de signature, KMS) n'est pas lui-même garant de l'écrivain unique — c'est le
bail qui l'est.

**EX-11.4** L'enregistreur ne détient que l'**identité d'usage** de la clé
(signer, lire la clé publique), jamais l'identité d'administration (créer,
supprimer, changer la politique de clé, exporter) : « Key administrators have
permissions to manage the KMS key, but do not have permissions to use the KMS
key in cryptographic operations » (AWS, R3 F-78) ; séparation entre
gestionnaires de clés (exemple : rôle Cloud KMS Admin) et utilisateurs de
clés chez Google (https://docs.cloud.google.com/kms/docs/separation-of-duties,
R3 F-79 ; le nom exact du rôle d'usage pour la signature n'a pas été lu),
Crypto Officer / Crypto User chez Azure (R3 F-80), capacités posées à la
création chez YubiHSM (R3 F-29). La cérémonie qui crée la clé et pose ces droits
est de CT-7 (11.6).

**EX-11.5** Quand le backend l'offre, la clé est créée **non exportable** et le
reste : `exportable: false` par défaut et irréversible chez Vault et OpenBao
(R3 F-21, F-26, F-75), « never leaves AWS KMS unencrypted » (R3 F-2),
« doesn't support EXPORT operations » chez Azure (R3 F-74), capacité
`exportable-under-wrap` non posée chez YubiHSM (R3 F-76), confirmation de clé
publique « works with non-extractable keys only » chez Luna (R3 F-60). Une
classe C (enveloppe) ne peut pas l'offrir : la graine est déchiffrée en
mémoire du démon ; la section 11.2 le dit.

**EX-11.6** Le démon DOIT **vérifier chaque signature** rendue par le backend
avec la clé publique de `recorder_key_id` (CT-1 §6.2, sans cofacteur) avant
d'écrire l'événement ; une signature qui ne vérifie pas est une panne du
signataire (section 14, mode dégradé « clé »), consignée. Motif : le format
binaire exact rendu par certains backends n'est pas documenté (AWS KMS, R3
NV-11), une bibliothèque PKCS#11 peut rendre `R ‖ S` sous une autre
convention, et la vérification coûte une opération Ed25519. La configuration
porte `signer.verify_after_sign: true`, non désactivable en version 0.

**EX-11.7** Certains backends bornent la taille du message signé : AWS KMS
Sign, `MessageType: RAW`, « Messages can be 0-4096 bytes » (R3 F-5) ; AWS
CloudHSM `CKM_CLOUDHSM_EDDSA`, « maximum 16,000 bytes » (R3 F-9, F-11). Le
message de CT-1 est `P_S ‖ C` (33 octets + la forme canonique de l'événement
sans `hash` ni `sig`). La configuration porte `signer.max_message_bytes`
(4096 pour AWS KMS, 16000 pour CloudHSM, `null` sinon). Quand un événement à
signer dépasse la borne, le noyau DOIT d'abord réduire ce que CT-1 permet de
réduire : `intent` devient une référence à une pièce `text/plain` (CT-1
§5.3 : « ou référence quand le texte est plus long ») ; si la borne reste
dépassée (approbation à très grand nombre de signataires : chaque couple
adresse-signature pèse 176 octets), l'événement n'est pas signé, l'appel est
traité en mode dégradé « clé » (bloquant) et le défaut est consigné. La
commande de validation (15.6) avertit quand `threshold.size` du jeu
d'approbateurs rend ce dépassement possible avec la borne configurée.

### 11.2 Classes de garde

| Classe | Principe | Où est la clé | Force | Backends |
|---|---|---|---|---|
| **A — matériel natif Ed25519** | Un module matériel ou son service signe en Ed25519 ; interface PKCS#11, mécanisme `CKM_EDDSA` (OASIS) ou propriétaire | Dans le module ; jamais en mémoire du démon | La plus forte : non exportable, attestation possible | PKCS#11 : Thales Luna, Entrust nShield, YubiHSM 2 (module PKCS#11 du fabricant), AWS CloudHSM (mécanisme propriétaire), Utimaco (à confirmer) |
| **B — service de signature** | Un service réseau détient la clé et signe en Ed25519 pur ; le démon s'authentifie auprès de lui | Dans le service | Forte si le service est non exportable et journalise ; dépend de la disponibilité du service (section 14) | Vault Transit, OpenBao Transit (type `ed25519`), AWS KMS (`ECC_NIST_EDWARDS25519`), Google Cloud KMS (`EC_SIGN_ED25519`, niveau SOFTWARE) |
| **C — enveloppe** | La graine Ed25519 (32 octets) est stockée chiffrée ou scellée ; un KMS la déchiffre (ou un TPM 2.0 la descelle sur des PCR) au démarrage, dans la mémoire du démon, qui signe lui-même | En mémoire du démon à l'exécution ; chiffrée au repos | Moyenne : la clé est exposée à qui lit la mémoire du démon ; la protection porte sur le repos et sur l'accès au KMS | AWS KMS (`Encrypt`/`Decrypt`, `GenerateDataKey`), Google Cloud KMS (`encrypt`/`decrypt`), Azure Key Vault et Managed HSM (`wrapKey`/`unwrapKey`), TPM 2.0 (`tpm2_create -L`, `tpm2_unseal -p pcr:…`) |
| **D — fichier** | La graine est dans un fichier (PKCS#8 de CT-1 §13), éventuellement chiffré par une phrase de passe | Sur disque et en mémoire | Développement seulement | fichier local ; SoftHSM2 (logiciel, mécanisme standard) assimilé à D |

**EX-11.8** La configuration (`signer.class`) nomme la classe et le backend
(`signer.backend.type`) ; la cohérence classe/backend est vérifiée au
démarrage. En `recorder.environment: "production"`, la classe **D est
refusée** (le démon ne démarre pas) ; la classe C est admise ; les classes A
et B sont recommandées. Le démon consigne au démarrage la classe, le type de
backend et l'identifiant de clé, jamais le secret d'accès.

**EX-11.9** En classe C, la donnée enveloppée est la **graine de 32 octets**
(RFC 8032), pas une clé de données intermédiaire : 32 octets tiennent dans la
borne la plus basse rencontrée, le scellement TPM 2.0 (« maximum size of 128
bytes », R3 F-70), et dans celles d'AWS KMS `Encrypt` (4096 octets, R3 F-62),
de Google Cloud KMS (64 KiB, R3 F-66) et d'Azure `wrapKey` (R3 F-68). Le
démon efface la graine de sa mémoire à l'arrêt ; un contexte de chiffrement
(AWS `EncryptionContext`, Google `additionalAuthenticatedData`) porte
`org_id`, `journal_id` et `key_id`, et jamais une donnée sensible (« This
field may be displayed in plaintext in CloudTrail logs », R3 F-63). Avec un
TPM 2.0, la politique de descellement lie la graine aux PCR choisis par le
client (`tpm2_createpolicy --policy-pcr -l sha256:0,1,2,3`, `tpm2_unseal -p
pcr:sha256:0,1,2,3`, R3 F-71, F-72) : un changement de micrologiciel ou de
chargeur rend la graine indescellable, ce qui est voulu et doit être prévu
dans la procédure de mise à jour (CT-8).

**Table des backends** — ce qui est établi par le digest R3, page par page.
« Non vérifié » renvoie aux points NV du digest.

| Backend | Classe | Signature Ed25519 pure | Détails établis | Attestation ou preuve d'origine | Source |
|---|---|---|---|---|---|
| **AWS KMS** | B | **Oui** : spécification de clé `ECC_NIST_EDWARDS25519` (« signing and verification only »), algorithme `ED25519_SHA_512` avec `MessageType: RAW` obligatoire, message ≤ 4096 octets ; `ED25519_PH_SHA_512` double-hache et est exclu (EX-11.1) | « The private key that generates signatures never leaves AWS KMS unencrypted » ; pas de rotation automatique des clés asymétriques (rotation manuelle) ; CloudTrail journalise tous les appels (`kms.amazonaws.com`) ; format binaire de la signature rendue : non vérifié (NV-11) | Aucune attestation exportable ; le registre consigne l'ARN et la non-exportabilité documentaire | https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html ; https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html ; https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html |
| **AWS CloudHSM** (Client SDK 5, PKCS#11 2.40) | A | **Oui**, mécanisme **propriétaire** `CKM_CLOUDHSM_EDDSA` (paramètre `NULL` = PureEdDSA, single-part, ≤ 16 000 octets), en-tête `cloudhsm_pkcs11_vendor_defs.h` ; **hsm2m.medium en mode non FIPS seulement** | Génération de la paire Ed25519 : `CKM_EC_EDWARDS_KEY_PAIR_GEN` absent de la liste ; non vérifié (NV-1) | Non lue | https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html |
| **Google Cloud KMS** | B | **Oui**, `EC_SIGN_ED25519` (« PureEdDSA mode, which takes raw data as input »), **niveau de protection SOFTWARE seulement** (absent des onglets hsm, hsm-single-tenant, external) | Pas de rotation automatique des clés asymétriques ; journaux Data Access (`AsymmetricSign`) à activer explicitement ; statut Preview/GA et borne de taille de `data` : non vérifiés (NV-2) | Aucune attestation exportable ; le registre consigne le nom de ressource | https://docs.cloud.google.com/kms/docs/algorithms ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; https://docs.cloud.google.com/kms/docs/key-rotation ; https://docs.cloud.google.com/kms/docs/audit-logging |
| **Azure Key Vault**, **Azure Managed HSM** | C seulement | **Non** : courbes P-256, P-256K, P-384, P-521 ; aucune occurrence d'Ed25519 ni d'EdDSA dans les deux pages ; le service signe un condensé, pas un message | Enveloppe par `wrapKey`/`unwrapKey` (`RSA-OAEP-256`, `A256KW`, `CKM_AES_KEY_WRAP`, …), permissions distinctes `wrapKey` / `unwrapKey` ; journal `AuditEvent` (`KeyWrap`, `KeyUnwrap`) ; rotation « at least every two years » ; page `unwrapKey` non lue (NV-10) | — | https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details ; https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 ; https://learn.microsoft.com/en-us/azure/key-vault/general/logging |
| **HashiCorp Vault Transit** | B | **Oui**, type `ed25519` (« supports signing, signature verification, and key derivation ») ; `hash_algorithm` ignoré pour ed25519 ; Ed25519ph seulement en Enterprise et exclu ici | `exportable: false` irréversible ; `auto_rotate_period` ≥ 1 h ; « In FIPS 140-3 mode, the following algorithms are not certified and thus should not be used: chacha20-poly1305 and ed25519 » ; audit devices HMAC-SHA256, fail-closed | — | https://developer.hashicorp.com/vault/api-docs/secret/transit ; https://developer.hashicorp.com/vault/docs/secrets/transit ; https://developer.hashicorp.com/vault/docs/audit |
| **OpenBao Transit** | B | **Oui**, type `ed25519`, formulation identique à Vault | `exportable: false` irréversible ; `auto_rotate_period` ≥ 1 h | — | https://openbao.org/docs/api/secret/transit/ ; https://openbao.org/docs/secrets/transit/ |
| **YubiHSM 2** | A | **Oui** : « EdDSA (Ed25519 only) », commande `SIGN EDDSA` sur les données brutes (« The DSI for EdDSA is the raw data D »), signature 64 octets ; capacité `sign-eddsa` | Export seulement sous enveloppe si la capacité `exportable-under-wrap` a été posée à la création ; YubiHSM 2 FIPS (140-3 niveau 2) : usage d'Ed25519 en mode approuvé non vérifié (NV-9) | Certificat X.509 d'attestation par la clé 0 (extensions `1.3.6.1.4.1.41482.4.x` : version, numéro de série, origine, domaines, capacités, identifiant d'objet, étiquette, FIPS) | https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html |
| **Thales Luna Network HSM 7** | A | **Oui**, `CKM_EDDSA` « compliant with "PureEDDSA" as defined in RFC 8032 », sans paramètre ; clés `CKK_EC_EDWARDS` ; `CKA_ECDSA_PARAMS` `"edwards25519"` ou OID `1.3.6.1.4.1.11591.15.1`, ASN.1 | **FIPS approuvé avec le micrologiciel 7.8.9 et plus** ; non approuvé en 7.8.4–7.8.7 ; version qui a introduit le mécanisme non vérifiée (NV-3) | Confirmation de clé publique `cmu getpkc` (PKCS#7, attribut `CKA_PKC`), « non-extractable keys only », pas sur HSM à FM ; clés Edwards : non vérifié (NV-3) | https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm ; https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm |
| **Entrust nShield** (Security World 13.9.3) | A | **Oui**, `CKM_EDDSA` (Sign & Verify), opérations single-part seulement, « The Ed25519 scheme requires no CK_EDDSA_PARAMS » ; `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Restrictions FIPS 140 niveau 3 et version introduisant EdDSA non vérifiées (NV-4) | Attestation `nfkmattest` (bundle JSON ; étapes WV1, MSCV1, MSCV2, KGCV1, KGCV2) prouvant que la clé « is generated in the nShield HSM and cannot be exported in clear text » | https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html ; https://nshielddocs.entrust.com/key-attestation-docs/intro.html |
| **Utimaco u.trust General Purpose HSM** | A (à confirmer) | Page produit : « EdDSA », « Edwards curves Ed25519 and Ed448 » | Mécanisme PKCS#11, micrologiciel, statut FIPS : **non vérifiés** (NV-6, fiche technique derrière un formulaire) | Non lue | https://utimaco.com/data-protection/gp-hsm/utrust-general-purpose-hsm |
| **SoftHSM2** 2.7.0 | D (logiciel) | **Oui**, mécanismes standard `CKM_EDDSA` (0x1057) et `CKM_EC_EDWARDS_KEY_PAIR_GEN` dans la branche de développement, en-tête Cryptoki 3.2 ; `--enable-eddsa` | Logiciel : développement et tests seulement ; version exacte du passage aux mécanismes standard non vérifiée (NV-13) | — | https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/NEWS ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/pkcs11/pkcs11.h |
| **TPM 2.0** | C seulement | **Non** par les outils : la page des algorithmes de `tpm2-tools` ne connaît ni `eddsa` ni `ed25519` ; `TPM_ALG_EDDSA` (0x0060) existe dans le registre TCG reproduit par la RFC 9684, mais la prise en charge réelle par les TPM et le profil PC Client sont non vérifiés (NV-5) | Scellement d'une donnée ≤ 128 octets avec politique PCR, objets `TPMA_OBJECT_FIXEDTPM`, `FIXEDPARENT` | — | https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/common/alg.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_create.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_unseal.1.md ; https://www.rfc-editor.org/rfc/rfc9684.txt |
| **Nitrokey HSM 2 / SmartCard-HSM** | aucune | **Non** : RSA, ECC (NIST, Koblitz, Brainpool), AES ; « the CC-certified crypto library of the SmartMX2 security controller […] does not support ed25519 » (déclaration de 2020 ; aucun document 2026, NV-7) | — | — | https://shop.nitrokey.com/shop/nitrokey-hsm-2-7 ; https://www.smartcard-hsm.com/features.html ; https://support.nitrokey.com/t/nitrokey-hsm2-support-for-ed25519/2484 |
| **Apple Secure Enclave** | aucune | **Non** : « Works only with NIST P-256 elliptic curve keys » | — | — | https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave |
| **Android StrongBox** | aucune | **Non** : RSA 2048, AES, ECDSA/ECDH P-256, HMAC-SHA256, 3DES ; Keystore hors StrongBox non tranché (NV-8) | — | — | https://developer.android.com/privacy-and-security/keystore |

**EX-11.10** Interface PKCS#11 (classe A) : le démon emploie `CKM_EDDSA`
(0x00001057) **sans paramètre** (schéma Ed25519 pur : « Ed25519 | Not
Required », table des schémas de la spécification 3.1 § 6.3.14, R3 F-54), sur
une clé `CKK_EC_EDWARDS` (0x00000040) dont `CKA_EC_PARAMS` porte `edwards25519`
(curveName, `13 0c 65 64 77 61 72 64 73 32 35 35 31 39`) ou l'OID `1.3.101.112`
(RFC 8410) selon le fournisseur — les deux formes sont incompatibles entre elles
(R3 F-51) et la configuration dit laquelle le jeton attend ; `C_Sign` en
**single-part** (seule forme admise par CloudHSM et nShield, R3 F-9, F-34) ;
signature attendue : 64 octets `R ‖ S` en petit-boutiste (R3 F-57), vérifiée
selon EX-11.6 ; clé publique lue dans `CKA_EC_POINT` (« Public key bytes in
little endian order as defined in RFC 8032 », R3 F-51). Le mécanisme
`CKM_CLOUDHSM_EDDSA` est admis par table de correspondance quand la
configuration le nomme.

**EX-11.11** Le profil Ed25519 de l'enregistreur **n'est pas un profil FIPS** :
Ed25519 n'est pas certifié en mode FIPS 140-3 chez Vault (R3 F-24), n'est
offert qu'en mode non FIPS sur CloudHSM (R3 F-10), et n'est approuvé sur Luna
qu'à partir du micrologiciel 7.8.9 (R3 F-31). Un client soumis à une exigence
FIPS l'apprend ici ; une courbe de remplacement (ECDSA P-256) demanderait un
format d'événement v1 et n'est pas dans le périmètre de CT-2.

### 11.3 Identifiant de clé, inscription et révocation

**EX-11.12** `recorder_key_id` suit CT-1 §3
(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`), est unique par organisation et ne désigne
jamais deux clés publiques différentes dans l'histoire d'un journal (CT-1
§11.2 : `key_id` et `public_key` uniques dans `cles.json`). Forme recommandée :
`rec-<nom de l'instance ou du journal>-<AAAA>-<nn>` (`rec-sinistres-2026-01`).
Le `key_id` du backend (étiquette PKCS#11, nom de clé Transit, ARN, nom de
ressource) est une donnée de configuration ; il n'apparaît pas dans
l'événement.

**EX-11.13** Avant le premier événement signé par une clé, sa clé publique DOIT
être inscrite au registre (`RecorderRegistry.registerRecorder(orgId,
journalId, chainKey, ed25519PubKey, sigs)`, signatures des approbateurs au
seuil, CT-4), **avec la clé de chaîne** qui lui est associée (EX-11.19) ;
l'enregistreur n'attend pas la confirmation d'inscription
pour écrire (le registre ne bloque jamais, section 14) mais consigne l'état
`inscription_en_attente` jusqu'à la lecture de `recorderByPubKey` ; le
dossier porte la validité « telle qu'annoncée » avec sa `source` (CT-1 §11.2)
et le contrôle 8 de CT-6 fait le reste. Le démon fournit à CT-4, par sa
ligne de commande ou son API de gestion : `key_id`, clé publique (32 octets,
hexadécimal `0x`), algorithme `ed25519`, classe de garde, type de backend,
date de création, l'**adresse de la clé de chaîne** (`chainKey`, 20 octets,
hexadécimal `0x`) et sa classe de garde, et, quand le backend la produit, la
**preuve d'origine**
(certificat d'attestation YubiHSM, PKC Luna, bundle `nfkmattest` nShield, R3
F-58 à F-61) que le registre PEUT consigner (CT-4).

**EX-11.14** La révocation d'une clé est un acte du registre (CT-4), qui
révoque la **clé de chaîne** sous laquelle la clé Ed25519 est inscrite
(`revokeRecorder(orgId, chainKey, sigs)`, `revokedAt` = instant du bloc) ;
côté enregistreur, un démon dont la clé courante est révoquée entre en mode
dégradé « clé » jusqu'à la rotation (11.4), et une clé révoquée n'est plus
proposée au signataire **sauf pour signer l'événement de rotation** qui la
remplace (CT-1 §8 exige que la rotation soit signée par l'ancienne clé). La
clé publique révoquée reste dans `cles.json` des dossiers avec sa validité
annoncée.

**EX-11.19** **Clé de chaîne.** Chaque clé Ed25519 de l'enregistreur est
inscrite au registre sous une **clé de chaîne** secp256k1 (`chainKey`,
adresse de 20 octets) : `RecorderRegistry` indexe un enregistreur par
`(orgId, chainKey)` ; c'est la clé de chaîne qui signe les ancres
(`AttestationRegistry.anchor`, signature EIP-191 de l'émetteur) et qui relaie
les clôtures (`PeriodRegistry.submitPeriod`). Les règles du contrat, lues
dans `contracts/RecorderRegistry.sol`, contraignent la gestion des clés :
une `chainKey` ne s'inscrit qu'une fois (« cle deja active »), une
`chainKey` révoquée ne se réinscrit jamais (« cle revoquee »), et une clé
Ed25519 n'est active que sous **une** `chainKey` à la fois (« cle Ed25519
deja active ») ; une fois cette `chainKey` révoquée, la même clé Ed25519
peut être inscrite sous une nouvelle. En conséquence :

1. **une clé de chaîne par clé Ed25519** : la configuration porte, dans
   `anchoring.registry`, la clé de chaîne courante (`chain_key` : classe de
   garde A à D comme en 11.2, backend ou référence de secret, adresse) et la
   suivante (`next_chain_key`, `null` hors rotation) ; la classe D est
   refusée en production, comme pour la clé Ed25519 ; le support de
   secp256k1 par chaque backend de la table de 11.2 n'a pas été recherché
   pour cette spécification (non vérifié) et se vérifie à la cérémonie
   (CT-7) ;
2. la clé de chaîne ne signe jamais un événement du journal, et la clé
   Ed25519 ne signe jamais une transaction : ce sont deux clés, deux usages ;
3. **rotation de la clé Ed25519** (EX-11.15) : la nouvelle paire (`chainKey`
   suivante, nouvelle clé Ed25519) est inscrite **avant** l'événement de
   rotation ; les périodes dont le manifeste est signé par l'ancienne clé
   sont ancrées avec l'ancienne `chainKey`, les suivantes avec la nouvelle ;
   l'ancienne `chainKey` est révoquée **après** la dernière ancre et la
   dernière soumission qu'elle doit porter ;
4. **rotation de la seule clé de chaîne** (compromission de la clé de
   chaîne, clé Ed25519 saine) : révoquer l'ancienne `chainKey`, puis inscrire
   la même clé Ed25519 sous la nouvelle ; entre les deux, les ancres
   attendent (le registre ne bloque jamais un appel, 14.2) ; aucun événement
   de rotation n'est écrit dans le journal, puisque la clé qui signe les
   événements ne change pas.

### 11.4 Rotation

La rotation est l'événement de CT-1 §8 : signé par l'ancienne clé,
contresigné par la nouvelle dans le corps, `valid_from = ts`, effet
`cle:<new_key_id>`. CT-2 fixe quand et comment elle est déclenchée.

**EX-11.15** Rotation planifiée. La configuration PEUT fixer une période
(`signer.rotation.planned_every_days`). Aucun éditeur lu n'écrit de période
pour une clé de signature asymétrique ; les périodes écrites visent les clés
de chiffrement : AWS, 365 jours par défaut (de 90 à 2560) pour la rotation
automatique des clés symétriques (R3 F-85,
https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html),
Google, « such as every 90 days » en exemple, sans rotation automatique des
clés asymétriques (R3 F-86,
https://docs.cloud.google.com/kms/docs/key-rotation), Azure, « rotate encryption
keys at least every two years » (R3 F-87,
https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation),
Vault et OpenBao, une rotation « periodic » sans chiffre (R3 F-88). Une
période DEVRAIT ne pas dépasser 730 jours : c'est un choix de cette
spécification, aligné sur la borne d'Azure pour les clés de chiffrement. La
rotation planifiée se déroule ainsi : (1) la nouvelle clé Ed25519 et la
nouvelle clé de chaîne sont créées dans leurs backends par l'identité
d'administration (cérémonie, CT-7), leurs identifiants sont inscrits dans
`signer.rotation.next_key_id` et `anchoring.registry.next_chain_key` ; (2) la
paire (nouvelle `chainKey`, nouvelle clé publique Ed25519) est inscrite au
registre (EX-11.13, EX-11.19 (3)) ; (3) à l'instant choisi, l'écrivain unique
fixe `seq` et `ts`, construit l'annonce `R` (dont `valid_from = ts`, CT-1
§8), obtient la contresignature de la nouvelle clé sur `P_R ‖ JCS(R)`, puis
scelle l'événement de rotation avec l'ancienne clé sur `P_S ‖ C`, et bascule
`recorder_key_id` pour l'événement suivant ; (4) les ancres passent à la
nouvelle `chainKey` selon EX-11.19 (3), puis l'ancienne `chainKey` est
révoquée au registre (CT-4) et l'ancienne clé Ed25519 est, dans le backend,
privée de la capacité de signer ; (5) le manifeste de la période en cours
sera signé par la nouvelle clé si la rotation est le dernier événement de la
période (CT-1 §10.1). Une rotation ne change ni le journal ni `seq`.

**EX-11.16** Rotation d'urgence. Sur soupçon de compromission de la clé
courante, et tant que cette clé reste utilisable par le démon légitime :
mêmes pas que la rotation planifiée, exécutés immédiatement et **dans cet
ordre** : inscription de la nouvelle paire, événement de rotation signé par
l'ancienne clé et contresigné par la nouvelle, **puis** révocation de
l'ancienne `chainKey` au registre. La validité de l'ancienne clé se ferme à
l'événement de rotation (`valid_to` fixé par l'événement, CT-1 §8, règle 3),
pas à l'instant de la révocation, que fixe le bloc (`revokedAt =
block.timestamp`) et que personne ne choisit. Révoquer d'abord laisserait le
démon sans droit de signer la rotation (EX-11.14 n'admet une clé révoquée
que pour cet événement, ce qui rend l'ordre inverse possible mais inutile :
il ouvre une fenêtre où la clé est révoquée sans successeur annoncé). Si la
clé courante n'est **plus utilisable** (module détruit, secret perdu, backend
injoignable sans
reprise), aucun événement de rotation signé par elle ne peut exister : le
journal ne peut pas être continué ; le démon reste en mode dégradé « clé »
(bloquant pour tout), l'ancienne clé est révoquée au registre, et la
poursuite se fait dans un **nouveau journal** (`journal_id` distinct, nouvelle
clé, `seq = 1`) dont le lien avec l'ancien est consigné au registre et dans
le journal d'exploitation, hors chaîne. Cette rupture est dite ici parce que
CT-1 l'impose : la continuité d'un journal passe par une signature de la clé
précédente.

**EX-11.17** Les ancres (CT-5) bornent la fenêtre de réécriture d'un
attaquant qui détient la clé à une heure (CT-1 §7.2) : la rotation d'urgence
ne « répare » pas les événements déjà signés, elle empêche les suivants.

### 11.5 Interface du signataire

**EX-11.18** Le noyau n'appelle le signataire qu'au travers d'une interface
unique, à trois opérations, implémentée par chaque backend :

| Opération | Entrée | Sortie | Règle |
|---|---|---|---|
| `public_key(key_id)` | identifiant de clé | 32 octets | Lue au démarrage et après rotation ; comparée à la clé inscrite au registre quand elle est disponible ; mise en cache. |
| `sign(key_id, message)` | identifiant, octets (`P_S ‖ C`, `P_SM ‖ C_M`, `P_R ‖ JCS(R)`) | 64 octets | Ed25519 pur ; délai `signer.timeout_ms` (défaut 5 000) ; aucune relance au-delà d'une seconde tentative ; vérification EX-11.6 avant tout usage ; le message n'est jamais journalisé (il contient la forme canonique de l'événement, dont les références, pas les pièces). |
| `health()` | — | `ok` ou raison | Appelée par la supervision (section 17) toutes les `signer.health_interval_ms` (défaut 10 000) et avant la sortie du mode dégradé « clé ». |

Le signataire des classes A et B est hors du démon (module, service) et
authentifié : code PIN ou identifiants PKCS#11 (référence de secret), jeton
Vault/OpenBao, identité IAM (AWS, Google) ; en classe C et D, il est une
fonction du démon sur la graine en mémoire. Les trois préfixes de domaine
sont ceux de CT-1 (annexe B) ; aucun autre message n'est jamais soumis au
signataire.

### 11.6 Cérémonie minimale (renvoi à CT-7)

La création de la clé, la pose des droits d'administration et d'usage, la
génération et la conservation de la preuve d'origine, la sauvegarde
(backends qui l'admettent sous enveloppe) et le procès-verbal sont la
**cérémonie des clés** de CT-7. CT-2 n'en fixe que les sorties nécessaires :
`key_id`, clé publique, classe, backend, preuve d'origine le cas échéant
(EX-11.13), et l'exigence que l'identité d'usage remise au démon ne permette
ni l'export, ni la suppression, ni la modification de la politique de clé
(EX-11.4). Les journaux du backend (CloudTrail pour KMS, Cloud Audit Logs
Data Access pour Google, `AuditEvent` pour Azure, audit devices pour Vault et
OpenBao, R3 F-81 à F-84) sont la contrepartie du journal d'exploitation de
l'enregistreur : le registre et CT-7 PEUVENT corréler un événement
(`recorder_key_id`, `ts`) avec l'appel de signature correspondant chez le
backend ; CT-2 n'exige pas cette corrélation.

## 12. Stockage en ajout seul

Le stockage est ce qui rend un événement **durable** avant que l'hôte reçoive
sa réponse (EX-4.19). Il est local au démon (volume dédié, EX-3.2), lisible
sans l'enregistreur par le vérificateur (CT-6) et par l'exportateur de dossier,
et copié vers un support WORM quand le client en a un. Les faits sur les
appels système, les formats de journaux d'écriture anticipée, les supports
WORM et la conservation suisse viennent du digest R5 (pages de manuel
man7.org, documentation PostgreSQL, SQLite et LevelDB, pages AWS, Azure,
Google, Exoscale, cloudscale, fedlex ; relus le 2026-10-22).

### 12.1 Disposition

**EX-12.1** Sous la racine `storage.root`, un répertoire par journal, nommé
par ses identifiants en hexadécimal minuscule sans `0x` :

```text
<root>/<org_id>/<journal_id>/
  segments/seg-<first_seq>-<epoch>.ndjson      événements (12.2) ; <first_seq> sur 16 chiffres, <epoch> sur 20 chiffres (entier non signé de 64 bits), zéros de tête
  pieces/<xx>/<sha256>                          pièces, nommées par leur sha256 sans 0x ; <xx> = deux premiers caractères (8.4)
  intentions/intentions-<epoch>.ndjson          journal d'intention (12.5)
  attente/attente-<epoch>.ndjson                événements en attente du mode dégradé (14.5)
  approbations/approbations-<epoch>.ndjson      jeux d'approbateurs des tickets et des décisions (EX-12.23)
  approbations/mac-<epoch>.ndjson               MAC de relais des appels retenus (EX-7.22, EX-12.23)
  manifestes/periode-<period_start>.json        manifeste de période (CT-1 §10) ; <period_start> en secondes UNIX, 10 chiffres
  manifestes/periode-<period_start>.sig         sa signature (CT-1 §10.2)
  journal.json                                  identité du journal (12.1), écrit une fois
```

`journal.json` est `{ "version": 0, "org_id", "journal_id", "created_at",
"recorder": "<version du logiciel>" }`, écrit à la création du journal et
jamais modifié ; il n'est pas une pièce et n'entre dans aucune chaîne. Il n'y a
**aucun fichier d'état mutable** : l'état de l'écrivain (dernier `seq`, dernier
`hash`, clé courante, époque) se dérive à la reprise des segments et de leurs
en-têtes (12.4), et ce que le noyau doit garder de plus pour les approbations
est écrit en ajout seul (EX-12.23). Les noms de fichiers sont ASCII et triables
: l'ordre lexicographique des segments est l'ordre des `first_seq`, puis des
époques. L'époque tient sur 20 chiffres parce qu'elle peut venir d'un compteur
de 64 bits partagé (la `mod_revision` d'etcd, compteur de toute la grappe ; le
`bigint` de PostgreSQL, 13.2) : sur 8 chiffres, une époque au-delà de 99 999
999 casserait le tri.

**EX-12.2** Le stockage DOIT être un système de fichiers local au démon ou un
volume bloc qui lui est attaché ; **jamais NFS** ni un partage SMB : « O_APPEND
may lead to corrupted files on NFS filesystems if more than one process
appends data to a file at once » et les verrous y sont émulés (`flock(2)`,
`nfs(5)`, R5 § 1.6, § 1.8). Un stockage partagé pour la haute disponibilité
(section 13) est un volume bloc attaché à un seul hôte à la fois, ou un
stockage objet avec écritures conditionnelles (12.6).

### 12.2 Format d'enregistrement et en-tête de segment

**EX-12.3** Un segment est un fichier texte UTF-8, sans marque d'ordre
d'octets, composé de lignes terminées par `\n` (U+000A seul) :

1. la **première ligne** est l'en-tête de segment, un objet JSON en JCS v0 :

   ```json
   {"epoch":3,"first_seq":1,"instance_id":"enregistreur-sinistres-1","journal_id":"0x41c2…5164","noortrace_segment":0,"opened_at":"2026-11-05T09:00:00.000Z","org_id":"0xa581…daab","prev_hash":"0x0000…0000","recorder":"0.1.0","recorder_key_id":"rec-test-01"}
   ```

   | Clé | Règle |
   |---|---|
   | `noortrace_segment` | constante `0` (version du format de segment) |
   | `org_id`, `journal_id` | ceux du journal |
   | `first_seq` | `seq` du premier événement que le segment contiendra (le dernier `seq` durable + 1 à l'ouverture) |
   | `prev_hash` | `hash` de l'événement `first_seq − 1`, ou 32 octets nuls si `first_seq = 1` : la chaîne se contrôle d'un segment à l'autre sans relire le précédent |
   | `epoch` | **jeton de clôture** du bail détenu à l'ouverture (section 13) ; entier ≥ 1 ; jamais dans un événement |
   | `recorder_key_id` | clé courante à l'ouverture (elle peut changer dans le segment par une rotation) |
   | `instance_id`, `recorder` | instance qui a ouvert le segment, version du logiciel |
   | `opened_at` | horodatage CT-1 §3 de l'ouverture |

2. chaque ligne suivante est **un événement complet** (dix-sept clés, `hash` et
   `sig` compris) en **JCS v0** (CT-1 §4), exactement les octets que
   `JCS_v0(E)` produit, suivis de `\n` ; aucune autre ligne, aucun
   commentaire, aucune ligne vide. L'exemple de ligne de segment de l'annexe
   A (2465 octets pour l'événement seq 4 de l'exemple de référence) est
   produit ainsi.

Les événements sont donc lisibles par n'importe quel lecteur NDJSON, et chaque
ligne porte sa propre preuve d'intégrité (`hash`, E-7) et d'authenticité
(`sig`, E-8) : il n'y a pas de somme de contrôle de ligne séparée (les formats
WAL de SQLite, LevelDB et PostgreSQL en portent une parce que leurs
enregistrements n'en portent pas eux-mêmes, R5 § 1.7). L'en-tête de segment
n'est pas signé : il est redondant avec la chaîne (12.4) et sert à la reprise
et à la clôture.

**EX-12.4** Un segment est **fermé** et un nouveau ouvert (a) après le dernier
événement dont le `ts` appartient à une période (frontière horaire, pour que
les segments s'alignent sur les manifestes) et (b) dès que la taille du
segment dépasserait `storage.segment_max_bytes` avec la ligne à écrire. Un
segment fermé n'est plus jamais ouvert en écriture. La fermeture n'ajoute
rien au fichier.

### 12.3 Durabilité

**EX-12.5** Le segment courant est ouvert `O_WRONLY | O_APPEND | O_CLOEXEC`
(« The modification of the file offset and the write operation are performed
as a single atomic step », `open(2)`, R5) par le seul écrivain. Chaque ligne
est écrite par une boucle qui réitère tant que `write(2)` rend moins que la
longueur demandée (« The number of bytes written may be less than count »,
`write(2)`, R5). Un succès de `write` n'est pas une durabilité (« A successful
return from write() does not make any guarantee that data has been committed
to disk », R5) : la durabilité est `fdatasync(2)` sur le descripteur du
segment (la taille change à chaque ajout, donc les métadonnées nécessaires
sont incluses, `fsync(2)`, R5), suivi, à la création d'un segment ou d'une
pièce, d'un `fsync` du répertoire parent (« an explicit fsync() on a file
descriptor for the directory is also needed », R5).

**EX-12.6** **Aucune réponse à l'hôte** pour un appel relayé, et aucun retour
`finAppel` au SDK, avant que `fdatasync` ait rendu sur le segment qui contient
l'événement de cet appel (EX-4.19, EX-6.3). La pièce « arguments » est forcée
sur disque (fichier puis répertoire) **avant** le relais (4.4 pas 4) ; les
pièces « résultat », « réponse », « prompt système » et « requête » avant
l'événement qui les référence ; une pièce est écrite dans un fichier
temporaire du même répertoire puis renommée sur son `sha256` (rename
atomique), et une pièce déjà présente sous ce nom n'est pas réécrite.

**EX-12.7** Validation groupée. L'écrivain PEUT regrouper plusieurs
événements sous un seul `fdatasync` : il écrit les lignes dans l'ordre des
`seq`, puis synchronise quand `storage.fsync.group_max_events` lignes sont en
attente ou que `storage.fsync.group_max_wait_ms` se sont écoulées depuis la
première ligne en attente (défauts 64 et 5). La réponse à chaque hôte n'est
rendue qu'après le `fdatasync` qui couvre sa ligne (EX-4.19). C'est ce qui
permet l'objectif de débit de la section 16 sans affaiblir la durabilité.

**EX-12.8** Une erreur de `fdatasync` ou de `write` (`EIO`, `ENOSPC`, autre)
est **fatale pour le segment** : `fsync(2)` ne promet pas qu'une erreur
d'écriture différée soit rapportée à nouveau ni que les pages en attente
soient conservées ; depuis Linux 4.13, elle est rapportée aux descripteurs
ouverts sur le fichier (« Since Linux 4.13, errors from write-back will be
reported to all file descriptors that might have written the data which
triggered the error », https://man7.org/linux/man-pages/man2/fsync.2.html,
R5). L'écrivain ferme le segment, relit le fichier depuis le début pour établir
sa dernière ligne valide (12.4), consigne, et entre en mode dégradé « stockage »
(section 14) ; les lignes dont la durabilité n'est pas établie sont tenues
pour perdues (leurs appels n'ont pas reçu de réponse, par EX-12.6, et leurs
intentions sont encore ouvertes, 12.5) ; un appel déjà relayé dont
l'événement était parmi elles suit EX-4.46 (événement gardé en attente,
`-31017`). À la sortie du mode dégradé, un nouveau segment est ouvert avec
`first_seq` = dernier `seq` valide + 1.

**EX-12.9** Le client DOIT déployer le démon sur un stockage dont le cache
d'écriture est protégé ou honore les commandes de vidage : « the memory in
the disk controller cache is volatile », « many of these [SSD] do not honor
cache flush commands by default » (documentation PostgreSQL sur la fiabilité,
R5). CT-8 en fait une exigence de déploiement ; CT-2 la nomme parce que sans
elle `fdatasync` ne prouve rien.

### 12.4 Détection d'écriture tronquée et reprise de l'écrivain

**EX-12.10** À chaque démarrage, et après toute erreur d'EX-12.8, l'écrivain
relit le journal avant d'écrire :

1. lister `segments/`, trier par nom ; vérifier que les `first_seq` se
   suivent (le `first_seq` d'un segment = dernier `seq` valide du précédent +
   1) et que les `epoch` ne décroissent pas ; une anomalie est consignée et
   bloque l'écriture (mode dégradé « stockage ») jusqu'à intervention ;
2. pour le **dernier** segment (les précédents sont réputés fermés
   proprement ; la supervision les contrôle à son rythme, 17), lire ligne à
   ligne : une ligne est **valide** si et seulement si elle se termine par
   `\n`, s'analyse en JSON strict (CT-1 §4 : clés uniques, pas de substitut
   isolé), valide contre `evenement-v0.schema.json`, a un `seq` égal au
   précédent + 1 (ou à `first_seq` pour la première), un `prev_hash` égal au
   `hash` précédent (ou à `prev_hash` de l'en-tête), un `hash` égal à celui
   recalculé (CT-1 §6.1) et une `sig` qui vérifie sous la clé en vigueur
   (CT-1 §6.2, §8) ; la **première ligne invalide ou incomplète** marque la
   fin du contenu durable : elle et tout ce qui la suit sont une écriture
   tronquée (règle de lecture de SQLite : seules les trames validées
   comptent, R5 § 1.7) ;
3. **tronquer** le fichier à la fin de la dernière ligne valide
   (`ftruncate`), `fdatasync`, consigner `segment_truncated` avec la
   longueur retirée et le `seq` attendu ; un segment réduit à son seul en-tête
   est conservé tel quel (il peut recevoir des lignes) ;
4. l'état de l'écrivain est alors : dernier `seq`, dernier `hash`, clé
   courante (dernière rotation lue), époque de l'en-tête ; si le bail courant
   a une époque supérieure, un nouveau segment est ouvert (EX-13.9) ;
5. rejouer le journal d'intention (12.5) puis le fichier d'attente (14.5),
   puis produire l'événement de politique s'il y a lieu, dans l'ordre unique
   d'EX-9.8.

**EX-12.11** Une ligne dont le `hash` recalculé diffère **n'est pas** une
troncature : c'est une altération ou une corruption de média. L'écrivain NE
DOIT PAS la tronquer en silence : il s'arrête en mode dégradé « stockage »,
consigne `segment_corrupted` avec le `seq` et les deux hachages, et attend une
intervention (restauration depuis la copie WORM, CT-8). La troncature de
EX-12.10 ne porte que sur une fin de fichier incomplète (ligne sans `\n` ou JSON
inachevé) ou sur des octets nuls de remplissage.

### 12.5 Journal d'intention et reprise après arrêt

Le journal d'intention est l'écriture anticipée **hors chaîne** qui rend
compte d'un appel d'écriture parti vers un serveur d'outils sans que son
événement ait pu être écrit (arrêt, panne) : sans lui, un effet produit chez
le client pourrait n'avoir aucune trace.

**EX-12.12** Pour tout appel de classe `ecriture` ou soumis à approbation, et
pour tout `debutAppel` du SDK de classe `ecriture`, l'écrivain ajoute au
fichier `intentions/intentions-<epoch>.ndjson` (ouvert `O_APPEND` comme un
segment) **deux lignes**, puis `fdatasync`, **avant** le relais (4.4 pas 8,
EX-6.3). Chaque ligne est le JCS intégral (section 8) d'un objet, suivi de
`\n`. La première est la ligne **intention**, celle de 4.4 pas 8 et de
l'annexe A, à neuf clés :

```json
{
  "intent_id": "i-00000000000000000001-000000000041",
  "upstream_id": "e-000000000041",
  "host": "agent-sinistres-stdio",
  "written_at": "2026-11-03T13:52:40.678Z",
  "org_id": "0x…", "journal_id": "0x…",
  "tool": "sap.payments.create",
  "arguments": { "sha256": "0x6cfc…bbb4", "length": 96, "redacted": true },
  "ticket": "apr-1192"
}
```

La seconde est la ligne **contexte d'intention**, qui porte l'événement
partiel nécessaire à la reprise :

```text
{
  "intent_context": "i-00000000000000000001-000000000041",
  "event": { "delegation": {…}, "code": {…}, "intent": …, "policy": {…}, "approval": …,
             "execution": { "tool": "sap.payments.create", "arguments": { "sha256": "0x…", "length": 96, "redacted": true } },
             "effects": [], "context": [ … ] }
}
```

| Clé | Règle |
|---|---|
| `intent_id` | `i-<époque>-<n>` : l'époque du bail de l'écrivain sur 20 chiffres et un compteur de l'écrivain sur 12 chiffres, strictement croissant dans l'époque ; l'époque étant strictement croissante à chaque acquisition du bail (EX-13.4), y compris après un redémarrage, `intent_id` est **unique dans le journal**, quel que soit le nombre de serveurs d'outils ou de redémarrages. Il ne dépend jamais de l'`id` JSON-RPC amont, qui n'est unique que par connexion amont |
| `upstream_id` | l'`id` JSON-RPC amont de l'appel (`e-` + douze chiffres, 4.4 pas 9) ou l'identifiant `call` du SDK ; pour le journal d'exploitation seulement |
| `host` | l'`id` de l'entrée de connexion d'hôte (`mcp.hosts`, `sdk.hosts`) |
| `written_at` | horloge murale à l'écriture |
| `org_id`, `journal_id`, `tool`, `ticket` | ceux de l'appel (`tool` = nom annoncé ; `ticket` ou `null`) |
| `arguments` | la **référence complète** de la pièce « arguments » (`sha256`, `length`, `redacted`, et `media_type` si elle en a un), telle qu'elle entrera dans l'événement |
| `intent_context` | l'`intent_id` de la ligne intention qui précède immédiatement |
| `event` | l'événement **partiel** tel que le noyau l'a déjà construit (section 7) : les clés `delegation`, `code`, `intent`, `policy`, `approval`, `execution` (réduit à `tool` et `arguments`), `effects` (ceux déclarés par le SDK, sinon `[]`), `context` ; sans `seq`, `ts`, `prev_hash`, `recorder_key_id`, `hash`, `sig`, ni `status`, `result`, `duration_ms`, `is_error`. C'est ce qui permet de construire l'événement de reprise sans la valeur en clair des arguments, qui n'existe plus. |

L'`intention_sha256` de l'événement de reprise (EX-12.14) est le SHA-256 de
la seule ligne intention (neuf clés), sans son `\n` : c'est la valeur que
l'annexe A calcule.

**EX-12.13** Quand l'événement de l'appel est durable (4.4 pas 13), l'écrivain
ajoute une ligne **levée** `{"lifted":"<intent_id>","seq":<seq>}` (JCS
intégral), sans `fdatasync` propre (elle est couverte par le prochain). Le
fichier d'intention est tourné avec le segment (nouvelle époque) et un
fichier dont toutes les intentions sont levées est supprimé à la rotation
suivante. Une ligne intention sans ligne contexte (arrêt entre les deux
écritures d'un même `fdatasync` : impossible par construction, mais une
corruption l'imiterait) donne à la reprise un événement construit **sans
rien fabriquer**, depuis la ligne intention et la chaîne durable :
`delegation` = `launched_by`, `scope` et `on_behalf_of` de configuration de
l'entrée `host`, `run_id: null` ; `code` = `model` et `prompt_version`
`null`, `policy_version` = celle du dernier événement de politique dont le
`ts` est au plus `written_at` ; `execution.arguments` = la référence
`arguments` de la ligne ; avec un `ticket` : `policy` = celle de l'événement
`retenue` de ce ticket (`a_approuver`, `rule`, `ticket`) et `approval` =
celui de l'événement de décision de ce ticket, tous deux relus dans la
chaîne ; sans `ticket` : `policy = { "rule": null, "decision": "autorise",
"ticket": null }`, `approval: null` ; `intent: null`, `context: []`, effets
par défaut de la classe (EX-7.6) ; note `intention_sans_contexte`. Si l'entrée
`host`, l'événement `retenue` ou la décision ne se retrouvent pas, l'écrivain
n'écrit pas d'événement de reprise : il entre en mode dégradé « stockage »
avec la note `intention_irreconstructible` et attend une intervention.

**EX-12.22** Le journal d'intention est relu ligne à ligne ; seule une
**dernière** ligne incomplète (sans `\n`, ou JSON inachevé) est une écriture
tronquée, coupée comme en EX-12.10. Une ligne illisible **suivie** d'autres
lignes est une corruption : l'écrivain n'ignore pas les intentions qui
suivent ; il consigne `intention_corrompue` (fichier, numéro de ligne) et
entre en mode dégradé « stockage » jusqu'à intervention, comme pour un
segment corrompu (EX-12.11).

**EX-12.14** Reprise. À la reprise (EX-12.10, pas 5), pour chaque intention sans
levée, dans l'ordre du fichier :

1. **levée implicite** : les **candidats** sont les événements durables
   d'`execution.status = "executee"`, de `ts` postérieur ou égal à
   `written_at`, dont `execution.tool`, `execution.arguments.sha256` et
   `policy.ticket` sont égaux à ceux de l'intention, et qui ne sont ni
   désignés par une ligne levée du journal d'intention (ils appartiennent à
   une autre intention), ni déjà appariés à une intention précédente de cette
   passe ; s'il y en a, l'intention est appariée au candidat de plus petit
   `seq` et tenue pour levée (le processus s'est arrêté entre le `fdatasync`
   de l'événement et l'écriture de la levée) : consigné
   `intention_levee_implicite`, rien n'est écrit dans la chaîne. Un événement
   `retenue` ou `refusee` n'est jamais candidat. Deux appels identiques et
   concurrents dont un seul événement est durable laissent ainsi l'autre
   intention sans candidat, et elle reçoit son événement de reprise ;
2. sinon, l'écrivain construit et scelle l'**événement de reprise** :
   l'événement partiel `event` de la ligne contexte, complété par `version: 0`,
   `seq`, `ts` (règle 7.4, instant de la reprise), `org_id`, `journal_id`,
   `recorder_key_id` courant, `prev_hash`, et `execution.status =
   "executee"`, `execution.is_error = true`, `execution.duration_ms = 0`
   (durée inconnue ; la valeur `0` est la convention de cette règle, CT-1
   exigeant un entier), `execution.result` = référence à la pièce JCS
   intégral de l'objet

   ```json
   {"intention_sha256":"0x…","noortrace_reprise":"resultat inconnu : enregistreur arrete pendant le relais"}
   ```

   où `intention_sha256` est le SHA-256 des octets de la ligne intention à
   neuf clés (son JCS intégral, sans le `\n`) ; `effects` : les effets
   déclarés dans la ligne contexte s'il y en a, sinon pour une classe `ecriture`
   l'effet unique par défaut d'EX-7.6 (le gabarit ne peut pas être évalué sans
   les valeurs en clair) ; `policy.redaction` selon EX-10.16 (la pièce
   « arguments » est celle de l'intention, avec son `redacted`). L'événement de
   reprise est un appel d'outil `executee` en erreur : le vérificateur de CT-1
   l'accepte tel quel (table 5.3), et un lecteur reconnaît la reprise à la clé
   `noortrace_reprise` de la pièce « résultat ».
3. la levée est écrite ; le journal d'exploitation reçoit `intent_recovered`
   (nom de 9.2) avec `intent_id`, `seq` de l'événement de reprise et
   `written_at`.

**EX-12.15** Le SDK produit la même reprise quand une session est fermée
(`fermer`) ou perdue avec un `debutAppel` d'écriture sans `finAppel`
(table de 6.2, `fermer`) ; le frontal MCP la produit quand le démon s'arrête
avec un relais d'écriture en vol (4.2, arrêt) : dans les deux cas, c'est la
relecture du journal d'intention qui fait le travail, pas un code spécial du
frontal.

### 12.6 Supports WORM

Le stockage local est modifiable au sens de l'Olico (12.7) ; la copie WORM
est une protection supplémentaire contre la réécriture par l'opérateur, qui
complète les ancres de CT-5 sans les remplacer. Les comportements ci-dessous
sont ceux des pages officielles lues (R5 § 1.1 à 1.5).

**EX-12.16** Quand `storage.seal.worm` est configuré, chaque segment **fermé**,
chaque manifeste et sa signature, et (si la rétention des pièces l'exige) les
pièces, sont copiés vers le support après fermeture, sous une clé d'objet qui
porte l'époque : `<prefix>/segments/seg-<first_seq>-<epoch>.ndjson`. La copie
est **conditionnelle à l'absence** de l'objet : S3 `PutObject` avec
`If-None-Match: *` (signature SigV4 obligatoire ; `412 Precondition Failed`
si un autre écrivain a gagné, `409 Conflict` à réessayer, R5 § 1.2) ; la
politique de bucket PEUT imposer la condition. Dans un bucket versionné
(obligatoire avec Object Lock), la condition ne porte que sur la **version
courante** : « The HTTP If-None-Match header only applies to the current
version of an object in a version bucket », et si cette version courante est
un marqueur de suppression, l'écriture réussit
(https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html,
R5 § 1.2) ; après un `DELETE` simple (qui pose un marqueur, 12.6), un
écrivain périmé pourrait donc réécrire la clé : la garantie d'EX-13.5 (3)
suppose que le rôle de l'enregistreur n'a pas `s3:DeleteObject`, et le
lecteur liste les **versions**. Le nom porte l'époque pour que
deux écrivains d'époques différentes ne se disputent jamais la même clé
(section 13). Une copie en échec est réessayée par la supervision et consignée
; elle ne bloque jamais un appel (section 14).

| Support | Ce que la page officielle établit | Réglage retenu |
|---|---|---|
| **Amazon S3 Object Lock** | WORM par **version** d'objet, versioning obligatoire, activation irréversible ; mode **Compliance** (« can't be overwritten or deleted by any user, including the root user » ; rétention non réductible) ; mode Governance contournable avec `s3:BypassGovernanceRetention` et l'en-tête `x-amz-bypass-governance-retention: true`, que la console ajoute par défaut ; un `DELETE` simple pose un marqueur (`200 OK`) sans détruire la version ; rétention prolongeable seulement ; `legal hold` indépendant | Bucket dédié, créé avec Object Lock ; `mode: "compliance"` recommandé, `governance` admis pour un environnement de test ; rétention par défaut du bucket = `retain_days` ; le rôle de l'enregistreur n'a jamais `s3:BypassGovernanceRetention` ; le lecteur liste les **versions**, pas la vue courante |
| **Azure Blob, stockage immuable** | WORM de niveau conteneur ou de niveau version (versioning requis ; activation au niveau compte seulement à la création) ; politique **verrouillée** requise pour la conformité (« Microsoft recommends that you lock the policy […] typically less than 24 hours ») ; rétention 1 jour à 146 000 jours, prolongeable ; cinq prolongations au plus pour une politique verrouillée de niveau conteneur ; `allowProtectedAppendWrites` pour les append blobs ; incompatible NFS 3.0 et SFTP | Conteneur dédié, politique de niveau version verrouillée ; les segments sont des **block blobs** écrits une fois après fermeture (pas d'append blob : le segment courant reste local) |
| **Google Cloud Storage** | Bucket Lock (politique de rétention verrouillée, irréversible, `400 BadRequestException` à toute réduction, 100 ans au plus) ; Object Retention Lock par objet, mode **Locked** (= `COMPLIANCE` en API XML, « permanently prevents the retention date from being reduced or removed ») ou Unlocked (= `GOVERNANCE`) ; `enableObjectRetention: true` à la création ; holds | Bucket dédié avec `enableObjectRetention`, configuration par objet en mode Locked avec `retain-until` = fin de rétention ; `mode: "compliance"` ↔ Locked |
| **Exoscale SOS** (Suisse) | Verrouillage S3 implémenté par le **legal hold** (« cannot be deleted indefinitely until the legal hold has been explicitly removed ») ; activation à la création du bucket seulement, versioning implicite ; exemple officiel de rétention par défaut en mode `GOVERNANCE` 30 jours ; gratuit ; mode `COMPLIANCE`, bornes et `bypass-governance` : **non documentés** (R5 § 2) | Type `s3-object-lock` ; `mode: "compliance"` à valider auprès de l'hébergeur ; à défaut, legal hold posé par l'enregistreur sur chaque objet et levé par un acte d'exploitation à l'échéance (CT-8) |
| **cloudscale.ch** (Suisse) | Object Lock documenté (objets protégés « for a predefined period of time »), à activer à la création du bucket ; **site RMA seulement** ; modes et legal hold non documentés (R5 § 2) | Type `s3-object-lock`, bucket au site RMA ; réglages à valider |
| Swisscom, Infomaniak S3/Swift | Aucune page officielle documentant un verrouillage ; Infomaniak écrit que l'immuabilité « is not available on other Swiss Backup storage protocols, such as Swift and S3 » (R5 § 1.5, § 2) | **Non retenus** comme support WORM |

**EX-12.17** Le support WORM reçoit des **copies** ; l'original local reste la
référence de l'écrivain pour la chaîne. À la reprise d'une instance dont le
stockage local est perdu (section 13), le journal est reconstruit depuis les
copies : la supervision vérifie périodiquement (17) que chaque segment fermé a
sa copie et que les octets sont identiques (`sha256` du fichier ; **pas**
l'ETag, qui « may or may not be an MD5 digest » et n'en est pas un pour
SSE-KMS, SSE-C et les objets multipart, R5 § 1.2).

**EX-12.18** En plus ou à la place du WORM distant,
`storage.seal.append_only_attribute` fait poser par une étape privilégiée
(`CAP_LINUX_IMMUTABLE`, « Only the superuser or a process possessing the
CAP_LINUX_IMMUTABLE capability can set or clear this attribute », `chattr(1)`,
R5) l'attribut `a` (append-only) sur le segment courant et le journal
d'intention, et `i` (immutable) sur chaque segment fermé et chaque manifeste.
L'attribut « will not affect the ability to write to already existing file
descriptors » (R5) : le démon garde son descripteur ouvert sur le segment
courant ; il dépend du système de fichiers (ext4, xfs, btrfs). Le démon lui-même
n'a pas cette capacité : c'est un service compagnon ou une tâche de
l'orchestrateur qui la pose (CT-8), de sorte qu'un démon compromis ne puisse pas
la retirer.

### 12.7 Rétention et purge des pièces

**EX-12.19** Les événements (segments), les manifestes et leurs signatures
sont conservés **au moins dix ans à compter de la fin de l'exercice** auquel
ils se rapportent : CO art. 958f al. 1 (« conservés pendant dix ans. Ce délai
court à partir de la fin de l'exercice », état au 1er octobre 2026, R5
§ 1.9), la rétention probatoire visée par l'architecture. La configuration
porte `storage.retention.events_years ≥ 10` ; la rétention WORM `retain_days`
DEVRAIT couvrir la fin de l'exercice en cours plus dix ans, soit jusqu'à
environ onze ans après l'écriture (R5, conséquences). Rien dans l'enregistreur
ne supprime un segment ; la fin de rétention est un acte d'exploitation
(CT-8).

**EX-12.20** Les **pièces** PEUVENT être purgées après
`storage.retention.pieces_days` (ou jamais, `null`) : la chaîne garde leurs
références (`sha256`, `length`, `redacted`), le dossier reste vérifiable sur
tout ce qui ne dépend pas du contenu (CT-1 §11.4 : E-6 sur une pièce fournie à
part devient « non exécuté, pièce absente », ce que le vérificateur dit), et le
client perd la capacité de produire la pièce. La purge est consignée dans le
journal d'exploitation avec la liste des `sha256` purgés et l'instant. L'Olico
exige un procès-verbal pour le transfert des données d'un support à un autre
(art. 10 al. 3) et la consignation des procédures (art. 9 al. 1 let. b ch. 4) ;
la consignation de la purge relève de cette seconde exigence
(https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2002/216/20130101/fr/pdf-a/fedlex-data-admin-ch-eli-cc-2002-216-20130101-fr-pdf-a.pdf,
R5 § 1.9).

**EX-12.21** Le stockage local et le stockage objet sont des **supports
modifiables** au sens de l'Olico (art. 9 al. 2 : « disques durs ou disques
amovibles, disques à l'état solide », R5) ; ils ne sont admis pour la
conservation qu'aux quatre conditions de l'art. 9 al. 1 let. b : un procédé
garantissant l'intégrité (« p. ex. signature électronique » : la signature
Ed25519 de chaque événement et de chaque manifeste), une preuve infalsifiable
du moment d'enregistrement (« p. ex. grâce à un système d'horodatage » : les
ancres de CT-5), le respect des prescriptions du procédé, et la consignation
des procédures et la conservation des journaux (« protocoles, journal de bord
des connexions [log files] » : le journal d'exploitation de la section 9.2 est
conservé avec le journal, même durée). Un support WORM **ne dispense pas** de
la signature et de l'horodatage. Le contrôle régulier d'intégrité et de
lisibilité (art. 10 al. 1) est la tâche de la supervision (17) : relecture
périodique des segments fermés selon EX-12.10, pas 2, et comparaison avec la
copie WORM.

### 12.8 Sauvegarde et restauration (renvoi à CT-8)

La sauvegarde du journal (segments, pièces, manifestes, journal d'intention,
fichiers des approbations, journal d'exploitation, `journal.json`), sa
restauration, la reconstruction depuis les copies WORM et la migration de
support avec procès-verbal (Olico art. 10 al. 2 et 3) sont de CT-8. CT-2
fixe ce qui les rend possibles : des fichiers texte en ajout seul, nommés de
façon triable, chacun porteur de ses preuves, et un état d'écrivain
entièrement dérivable des fichiers (EX-12.1).

### 12.9 Fichiers des approbations

**EX-12.23** Le noyau garde hors chaîne, en ajout seul, ce que CT-3 lui
demande de conserver et que la chaîne ne porte pas : l'`approver_set` de la
réponse `nouveau` de chaque ticket et de chaque remise, pour expirer seul un
ticket (EX-9.4, CT-3 EX-12.11) ; l'`approver_set` de chaque décision
scellée, pour l'exportateur (CT-3 EX-8.9) ; le MAC de relais de chaque
`retenue` (EX-7.22) ; les continuations MRTR d'un appel approuvé et leur
usage (EX-4.21). Deux fichiers par époque, ouverts `O_APPEND` comme un
segment, chaque ligne étant le JCS intégral d'un objet suivi de `\n` :

1. `approbations/approbations-<epoch>.ndjson`, lignes :
   - `{ "kind": "retenue", "ticket", "request_seq", "request_hash",
     "approver_set" }`, écrite par l'écrivain après la signature de
     l'événement `retenue` et **avant** son ajout au segment, `fdatasync`
     (4.4 pas 6) : une `retenue` de la chaîne a toujours sa ligne et sa
     ligne `mac`, et le noyau a toujours de quoi expirer seul le ticket
     (EX-9.4), même si le service a perdu son état ;
   - `{ "kind": "remise", "ticket", "remise_id", "decision",
     "approver_set" }`, écrite à la réception d'une remise hors mode
     dégradé, `fdatasync` avant sa vérification (EX-7.19) ;
   - `{ "kind": "decision", "ticket", "seq", "hash", "approver_set" }`,
     écrite par l'écrivain après la signature de l'événement de décision et
     avant son ajout au segment, `fdatasync`, donc avant `acquitter`
     `scelle` ou `expiration` ; `approver_set` est celui de la remise
     scellée ou, pour une expiration par le noyau seul, celui d'EX-9.4 ;
   - `{ "kind": "continuation", "ticket", "seq", "hash",
     "request_state_sha256" }`, écrite pour un résultat `input_required`
     d'un appel qui porte l'approbation d'un ticket (`seq` et `hash` de son
     événement `executee`, `sha256` du `requestState` en hexadécimal `0x`),
     `fdatasync` avant le relais du résultat à l'hôte (4.4 pas 14,
     EX-4.21) ;
   - `{ "kind": "continuation_consommee", "ticket", "request_state_sha256" }`,
     écrite quand une continuation de ce `requestState` passe RL-3,
     `fdatasync` avant son intention (4.4 pas 8) ;
2. `approbations/mac-<epoch>.ndjson` : une première ligne de contrôle
   `{ "kind": "controle", "mac" }` (EX-7.22), puis des lignes `{ "ticket",
   "request_hash", "mac" }` (`mac` en hexadécimal `0x`, 32 octets), écrites
   avec la ligne `retenue` et sous le même `fdatasync`.

Le fichier `approbations-<epoch>` est conservé aussi longtemps que les
segments (EX-12.19) et sauvegardé avec eux (12.8) : il ne porte que des
adresses d'approbateurs, des seuils et la `source` déclarée. Un fichier
`mac-<epoch>` est supprimé à la première rotation qui suit l'instant où
toutes ses lignes de MAC sont échues : une ligne ne sert plus après
`request_ts + 2E`, puisqu'une décision est scellée avant `request_ts + E`
(SG-4) et que RL-4 refuse tout relais à partir de `approval.at + E`. À la
reprise et après une bascule, l'écrivain relit, dans l'ordre des époques,
tous les fichiers `approbations-*` et les fichiers `mac-*` restants ; seule
une dernière ligne incomplète est une écriture tronquée, coupée comme en
EX-12.10, et une ligne illisible suivie d'autres lignes est une corruption,
traitée comme en EX-12.22. Les lignes étant écrites avant l'ajout de leur
événement au segment, un arrêt entre les deux laisse une ligne dont
l'événement n'est pas dans la chaîne (son `hash` n'y figure pas) : elle est
ignorée. Si une décision du journal n'a pas sa ligne `decision` (fichier
incomplet, par exemple une copie restaurée sans ses dernières lignes, 12.8),
son `approver_set` est celui de la dernière ligne `remise` de son ticket qui
porte sa `decision` et dont le jeu est exploitable (EX-7.16), et, pour une
décision `expire`, celui que donne la règle d'EX-9.4 (dernière ligne `remise`
au jeu exploitable, de toute décision, sinon la ligne `retenue`), la même
que celle de l'expiration par le noyau seul. Une `retenue` sans ligne `mac`
ne peut pas être relayée, RL-2 échouant : l'échec est fermé. Une
continuation dont le `requestState` n'a pas de ligne `continuation`
repasse par le pas 3 (EX-4.21). L'exportateur de dossier écrit dans
`approbations.json` (CT-1 §11.2) l'`approver_set` de la ligne `decision` de
la décision, tel quel ; sa `source` est celle que le service a déclarée
(CT-3 EX-8.8).

## 13. Haute disponibilité à écrivain unique avec bail

### 13.1 Modèle

Un journal a **un seul écrivain** à la fois (CT-1 §7 : `seq` sans trou,
`prev_hash`, `ts` non décroissant ; EX-7.8). La haute disponibilité consiste
à pouvoir changer d'écrivain sans violer ces invariants ni perdre d'événement
durable. Le mécanisme est un **bail** (droit exclusif d'écrire, à durée
limitée) assorti d'un **jeton de clôture** (époque, entier strictement
croissant à chaque acquisition), parce qu'un bail seul ne protège pas contre
un écrivain qui croit encore le détenir après une pause : « if the GC pause
lasts longer than the lease expiry period, and the client doesn't realise
that it has expired, it may go ahead and make some unsafe change » ; « you
need to include a fencing token with every write request to the storage
service […] a number that increases […] every time a client acquires the
lock » ; « this requires the storage server to take an active role in
checking tokens » (Kleppmann, 2016, R5 § 1.8 ; la page officielle de Redis le
recommande aussi : « You should implement fencing tokens », R5).

**EX-13.1** Un enregistreur n'écrit un journal que s'il détient le bail de ce
journal ; l'époque du bail est inscrite dans l'en-tête de chaque segment,
intention et fichier d'attente qu'il ouvre (EX-12.3) et dans le nom de chaque
objet WORM (EX-12.16), jamais dans un événement. Le vérificateur de CT-1
ignore l'époque : la chaîne ne dépend pas de la haute disponibilité.

**EX-13.2** La haute disponibilité à bascule exige que les segments, les
pièces, le journal d'intention et le fichier d'attente soient accessibles au
repreneur : volume bloc rattachable à un autre hôte, ou reconstruction depuis
les copies WORM (EX-12.17) pour les segments fermés et depuis le dernier
segment ouvert si le volume survit. Sans stockage accessible, il n'y a pas de
bascule, seulement un redémarrage sur le même hôte (le bail reste utile :
il protège contre un second processus sur cet hôte). Le volume DOIT être
**monté de façon exclusive** (attaché à un seul hôte et à un seul processus
écrivain à la fois) : en Kubernetes, un volume `ReadWriteOnce` « still can
allow multiple pods to access » s'ils sont sur le même nœud, et c'est
`ReadWriteOncePod` qui réserve le volume à un seul pod (documentation des
volumes persistants de Kubernetes,
https://kubernetes.io/docs/concepts/storage/persistent-volumes/, lue le
2026-10-22).

### 13.2 Magasins de bail

Le magasin de bail est nommé par `lease.store`. Trois magasins en version 0,
ceux que le digest R5 établit ; Redis et Redlock sont **exclus** : « it does
not have any facility for generating fencing tokens » et « Redis is not using
monotonic clock for TTL expiration mechanism » (Kleppmann ; page officielle
Redis, R5).

| Magasin | Portée | Acquisition | Renouvellement | Époque | Établi par |
|---|---|---|---|---|---|
| **`file`** (verrou de fichier) | **Un seul hôte** : plusieurs processus sur la même machine. `flock(2)` est émulé sur NFS en verrous d'étendue et rendu purement local par `nolock`/`local_lock` (R5 § 1.8) : inutilisable entre hôtes | `flock(LOCK_EX \| LOCK_NB)` sur `lease.store.path` ; en cas de succès, lire le fichier `path.epoch` (entier décimal), écrire `epoch + 1`, `fdatasync` | Implicite tant que le descripteur est ouvert ; le noyau du système libère à la mort du processus | le contenu de `path.epoch` après incrément | man7 `flock(2)`, `nfs(5)` |
| **`postgresql`** | Plusieurs hôtes | Table `lease(name text primary key, holder text, epoch bigint, expires_at timestamptz)` ; une ligne par journal (`name = "<org_id>/<journal_id>"`) ; acquisition par un `UPDATE` conditionnel : `UPDATE lease SET holder = $instance, epoch = epoch + 1, expires_at = clock_timestamp() + $ttl WHERE name = $name AND (holder IS NULL OR expires_at < clock_timestamp()) RETURNING epoch` ; en Read Committed, la clause `WHERE` est réévaluée sur la version mise à jour de la ligne, de sorte qu'un seul des `UPDATE` concurrents réussit (documentation PostgreSQL sur l'isolation, R5) ; `clock_timestamp()` et non `now()`, figé au début de la transaction (R5) | `UPDATE lease SET expires_at = clock_timestamp() + $ttl WHERE name = $name AND holder = $instance AND epoch = $epoch` ; zéro ligne mise à jour = bail perdu | la colonne `epoch` rendue | pages `transaction-iso`, `functions-datetime` ; les verrous consultatifs (`pg_try_advisory_lock`) ne produisent pas de jeton et ne sont pas employés |
| **`etcd`** (v3) | Plusieurs hôtes | `LeaseGrant(ttl)` puis `Txn` : `If(Version(key) == 0) Then(Put(key, instance, WithLease(lease)))` ; la transaction est atomique (« All comparisons are applied atomically », R5) ; la clé `key = <prefix><org_id>/<journal_id>` disparaît à l'expiration du bail etcd (« all keys attached to that lease will be deleted ») | `LeaseKeepAlive` ; un `Txn` qui vérifie que la clé porte encore `instance` | la **`mod_revision`** de la clé rendue par le `Put` : la révision du magasin est « a 64-bit cluster-wide counter […] incremented each time the key space is modified » (R5), donc strictement croissante entre deux acquisitions | page `learning/api` v3.5 |

**EX-13.3** Les durées : `lease.ttl_ms` (défaut 10 000), `lease.renew_ms`
(défaut 3 000, soit moins du tiers du TTL), `lease.acquire_wait_ms` (attente
avant d'abandonner l'acquisition au démarrage). Le démon mesure les délais sur
son **horloge monotone** : le bail est tenu pour valide jusqu'à `t_renew +
ttl_ms − marge` où `t_renew` est l'instant monotone du dernier renouvellement
réussi et `marge = lease.renew_ms` (une borne sur le temps que le magasin a pu
mettre à enregistrer le renouvellement). Les horloges murales des hôtes ne
participent pas au raisonnement de validité ; pour PostgreSQL, c'est
l'horloge du serveur de base de données qui tranche l'expiration, et un
renouvellement n'est tenu pour réussi qu'à la réception de la réponse.

### 13.3 Jeton de clôture et écritures conditionnelles

**EX-13.4** L'époque obtenue à l'acquisition est le jeton de clôture de
l'écrivain pour toute la durée où il détient le bail sans interruption. Elle
est **strictement croissante** à chaque acquisition par n'importe quel
écrivain (propriété du magasin, 13.2).

**EX-13.5** Le stockage **vérifie le jeton** à chaque point où un écrivain
périmé pourrait nuire :

1. **ouverture d'un segment, d'un fichier d'intention ou d'attente** : l'époque
   de l'en-tête DOIT être strictement supérieure à la plus grande époque
   présente dans les noms de fichiers du répertoire ; sinon l'ouverture est
   refusée (un écrivain d'époque inférieure a perdu son bail) ;
2. **scellement** (pose de l'attribut immutable, copie WORM) : l'étape de
   scellement refuse un segment dont l'époque est inférieure à celle du
   dernier segment scellé (R5, conséquences) ;
3. **stockage objet** : la clé porte l'époque et l'écriture est conditionnelle
   (`If-None-Match: *`) : « the first write operation to finish succeeds […]
   subsequent writes [fail] with a 412 Precondition Failed » (R5 § 1.2) ; un
   écrivain périmé ne peut donc ni écraser ni s'intercaler.

**EX-13.6** L'écrivain **vérifie son bail avant chaque `fdatasync`** d'un
segment (EX-12.5) et avant chaque appel au signataire (EX-11.3) : si le bail
n'est plus tenu pour valide (13.3), il n'exécute pas l'opération, consigne
`lease_lost`, cesse d'écrire et entre en mode dégradé « bail » (section 14) ;
les appels non relayés dont l'événement n'a pas été rendu durable reçoivent
`-31010`, les appels déjà relayés `-31017` (EX-4.46). Il ne reprend qu'après
une nouvelle acquisition, avec une nouvelle époque et un nouveau segment
(12.4). Un écrivain qui a perdu son bail NE DOIT PAS tenter de le reprendre
« à chaud » sans relire le journal (EX-12.10) : un autre a pu écrire
entre-temps. Ces deux contrôles sont faits par l'écrivain lui-même ; le
système de fichiers local ne vérifie aucun jeton, et une pause plus longue
que la marge entre le contrôle et la fin de `fdatasync` suffit à écrire avec
un bail expiré : c'est précisément le cas que la citation de 13.1 déclare non
sûr. EX-13.10 ferme cette fenêtre.

**EX-13.10** **Clôture par le stockage et contrôle après écriture.** Un
déploiement à bascule entre hôtes (`lease.store` `postgresql` ou `etcd`)
DOIT satisfaire les trois règles suivantes :

1. **le repreneur rend le stockage du prédécesseur inaccessible en écriture
   avant de le relire** (13.4 pas 4) : par un détachement forcé du volume de
   l'hôte précédent (ou l'arrêt forcé de cet hôte par l'orchestrateur), ou
   par une réservation persistante SCSI ou NVMe qui exclut l'ancien
   initiateur (le support selon le type de volume n'est pas vérifié ici) ;
   les attributs `a` et `i` ne suffisent pas, puisque « Setting 'a' and 'i'
   attributes will not affect the ability to write to already existing file
   descriptors » (`chattr(1)`, R5 § 1.6) ; la configuration nomme le moyen
   (`lease.fencing` : `"detachement"` ou `"reservation"`), et la validation
   refuse une bascule entre hôtes sans moyen ;
2. **l'écrivain revérifie l'époque auprès du magasin de bail après le
   `fdatasync` et avant de répondre** à l'hôte (lecture de la ligne de bail
   PostgreSQL, ou `Txn` etcd qui compare la clé) : si l'époque du magasin
   n'est plus la sienne, il ne répond pas comme si l'événement était acquis
   (`-31017`, EX-4.46), consigne `lease_lost_after_write` avec le `seq`, et
   s'arrête d'écrire ; la validation groupée amortit ce contrôle sur le
   groupe (EX-12.7) ;
3. **le repreneur consigne la taille finale** de chaque fichier
   d'époque inférieure après l'avoir rendu non inscriptible, et la
   supervision (17.5) signale toute croissance ultérieure comme une
   **fourche** (`journal_fork`, alerte critique).

Le magasin `file` (verrou `flock(2)` tenu tant que le processus vit, libéré
par le noyau à sa mort) est sûr sur **un seul hôte** : un processus figé
garde son verrou, et aucun second processus ne peut acquérir le bail tant
qu'il vit ; il ne sert pas entre hôtes (13.2).

### 13.4 Bascule, pas à pas

Instances `A` (active) et `B` (passive), même configuration, même journal,
stockage accessible aux deux (13.1) ; leurs références de secrets se
résolvent vers les mêmes octets, en particulier `storage.relay_mac_key`
(EX-7.22), sans quoi `B` ne pourrait relayer aucun appel approuvé dont `A` a
scellé la `retenue`.

1. `B` démarre, valide sa configuration (15.4) et compare la ligne de
   contrôle de sa clé du MAC de relais à celle du dernier fichier `mac-*` de
   `A` (EX-7.22) : une différence est une erreur de configuration
   (`relay_mac_key_mismatch`), et `B` ne prend pas le bail ; puis `B` essaie
   d'acquérir le bail ;
   échec tant que `A` le renouvelle ; `B` réessaie toutes les `lease.renew_ms`
   et répond aux hôtes qui la joindraient `-31010` (`reason:
   "bail_non_detenu"`) ; sa santé est `standby` (17).
2. `A` s'arrête, est isolée ou cesse de renouveler ; au plus `lease.ttl_ms`
   après son dernier renouvellement, le magasin tient le bail pour expiré.
3. `B` acquiert le bail avec l'époque `e+1`.
4. `B` rend les fichiers d'époque inférieure non inscriptibles et consigne
   leur taille (EX-13.10 (1) et (3)), puis relit le journal (EX-12.10) :
   liste des segments, validation du dernier, troncature d'une fin
   incomplète, dernier `(seq, hash)`, clé courante.
5. `B` ouvre un nouveau segment `seg-<seq+1>-<e+1>.ndjson` avec `prev_hash` =
   dernier `hash`, et un nouveau fichier d'intention ; EX-13.5 (1) passe
   puisque `e+1 >` toute époque présente.
6. `B` rejoue le journal d'intention de `A` (12.5) : les écritures en vol
   deviennent des événements de reprise ; puis le fichier d'attente (14.5).
   Elle relit les fichiers des approbations (EX-12.23) ; elle seule échange
   désormais avec le service d'approbation : `charger`, `ouvrir` pour les
   tickets sans décision, `consommer` à renvoyer, puis `decisions` (EX-7.14).
7. `B` accepte les connexions d'hôtes (la bascule d'adresse — VIP, DNS,
   répartiteur — est du déploiement, CT-8 ; MCP n'a pas de redirection) ;
   santé `ok`.
8. Si `A` revient : son bail est périmé (13.3) ; EX-13.6 l'empêche d'écrire
   ; si elle tentait d'ouvrir un segment avec `e`, EX-13.5 (1) le refuse ;
   ses copies WORM seraient refusées en `412`. `A` redevient passive et
   relit le journal avant toute nouvelle acquisition.

### 13.5 Pertes admises

Dites en clair, parce qu'une haute disponibilité qui promet « aucune perte »
ment :

- **Les appels en vol de `A`** : un appel d'écriture relayé sans événement
  durable devient un événement de reprise (`is_error: true`, résultat
  inconnu), pas l'événement qu'il aurait été ; l'hôte n'a pas reçu de réponse
  et ré-émettra peut-être l'appel, ce qui donne un second événement. Un appel
  de lecture en vol est perdu sans trace s'il n'avait pas atteint le
  stockage (son intention n'est pas écrite : c'est la définition d'une
  lecture).
- **Les événements en attente du mode dégradé** (14.5) : ils sont dans le
  fichier d'attente de `A` (`fdatasync` au mieux) ; perdus si ce fichier n'est
  pas accessible à `B`.
- **La fenêtre `ttl_ms`** : pendant au plus `lease.ttl_ms`, aucun écrivain ;
  les hôtes reçoivent `-31010` ou ne joignent personne.
- **Le segment ouvert de `A`** : si le volume de `A` est perdu, les événements
  de ce segment non encore copiés en WORM (la copie se fait à la fermeture,
  EX-12.16) sont perdus ; leurs appels avaient reçu une réponse. C'est la
  perte la plus grave : elle se borne par `storage.segment_max_bytes` et par
  la rotation horaire, et elle est visible (le manifeste de la période ne
  pourra pas être produit, ou le sera sur un journal tronqué, ce que P-3 et le
  registre révèlent). Un client qui ne l'admet pas emploie un volume bloc
  répliqué de façon synchrone (CT-8).
- **Les horloges** : `B` date la reprise avec sa propre horloge ; `ts` reste
  non décroissant par la règle 7.4.
- **La fourche**, si EX-13.10 n'est pas appliquée : `A` vérifie son bail
  (valide encore 5 s), se fige 12 s avant `write` et `fdatasync` de `seq
  N+1` ; `B` acquiert l'époque `e+1` à 10 s, relit le segment de `A`
  (dernier `seq N`) et ouvre `seg-(N+1)-(e+1)` ; `A` reprend et ajoute son
  propre `seq N+1` à son ancien segment par le descripteur `O_APPEND` qu'il
  avait ouvert, que ni l'époque de `B` ni un attribut `i` posé après coup
  ne révoquent. Il existe alors deux
  événements signés de `seq N+1`, l'effet de l'appel de `A` est absent de la
  chaîne de `B`, et la relecture suivante (EX-12.10, pas 1) bloque l'écriture
  jusqu'à intervention. EX-13.10 (1) rend l'écriture de `A` impossible, (2)
  l'empêche de répondre comme si elle était acquise, (3) la rend visible ;
  sans eux, la fourche est possible et seule la supervision peut la
  découvrir.

### 13.6 Plusieurs hôtes, plusieurs journaux

**EX-13.7** Un démon PEUT tenir plusieurs journaux (un bail, un écrivain, un
répertoire par journal) ; un journal n'a jamais deux démons écrivains. Une
connexion d'hôte est rattachée à un journal par la configuration (`recorder`
d'une instance mono-journal en version 0 : un démon, un journal ; la
configuration multi-journal est de la version 1, section 21).

**EX-13.8** Plusieurs hôtes parlent au même démon : la sérialisation des
`seq` est celle de l'écrivain unique (EX-7.8), quel que soit le nombre de
connexions ; la latence ajoutée par appel en dépend (section 16).

**EX-13.9** À la reprise sur le même hôte après un arrêt propre ou un plantage
sans bascule, le démon réacquiert le bail (nouvelle époque), relit le journal
et ouvre un nouveau segment : le segment précédent est fermé par sa seule
existence (aucun marqueur de fin). Deux segments consécutifs d'époques
différentes sont donc la trace normale d'un redémarrage.

## 14. Comportement en panne

La règle de l'architecture est reprise telle quelle : **bloquant** pour les
écritures et pour les actions soumises à approbation, **passant** pour les
lectures, réglable par le client, par outil. Un appel est « bloqué » quand
l'enregistreur ne le relaie pas et rend une erreur JSON-RPC ; « passant »
quand il est relayé sans que l'événement soit durable à l'instant de la
réponse, l'événement étant mis en attente (14.5) ; « retardé » quand
l'enregistreur attend un délai borné avant de décider. Les codes et messages
rendus sont ceux de la table de 4.4 (EX-4.24) ; aucune panne ne produit un
code nouveau. L'attente d'une approbation et le refus d'un ticket ne sont
pas des pannes : l'hôte reçoit le signal d'approbation, un résultat d'outil
(EX-4.49).

### 14.1 Classification des outils

**EX-14.1** La **classe** d'un outil (`lecture` ou `ecriture`) est, dans
l'ordre : (1) `policy.servers.<alias>.tools.<nom d'origine>.class` si non
nul ; (2) `policy.servers.<alias>.class_default` si non nul ; (3)
`annotations.readOnlyHint === true` dans la définition annoncée par le
serveur → `lecture`, **indication non fiable** (« clients MUST consider tool
annotations to be untrusted unless they come from trusted servers », page
Tools de la spécification MCP, R1 Q3 ; EX-4.17) ; (4) à défaut, `ecriture`.
Un appel **soumis à approbation** (`policy.decision = "a_approuver"`, ce qui
comprend l'appel relayé après approbation, qui reprend la `policy` de l'appel
retenu, EX-7.12) est traité comme `ecriture` pour cette section quelle que
soit sa classe. Le SDK déclare la classe dans
`debutAppel` ; à défaut, la configuration ; à défaut `ecriture` (6.2).

**EX-14.2** Le **comportement en mode dégradé** d'un outil est, dans l'ordre :
`policy.servers.<alias>.tools.<nom>.failure` si non nul ; sinon
`policy.failure.lecture` ou `policy.failure.ecriture` selon la classe. La
valeur `policy.failure.ecriture` est **constante `bloquant`** : une écriture
sans événement durable n'est jamais relayée, c'est la promesse du produit
(EX-4.19). Un client PEUT rendre les lectures bloquantes
(`policy.failure.lecture: "bloquant"`) ; il PEUT rendre un outil de classe
`ecriture` passant **seulement par outil et explicitement**
(`tools.<nom>.failure: "passant"`), et la commande de validation (15.6)
l'affiche comme un avertissement nominatif : c'est un outil dont les effets
pourront n'avoir qu'un événement en attente.

### 14.2 Matrice

Colonnes : **E** = écritures et actions soumises à approbation ; **L** =
lectures (avec `failure.lecture: "passant"`, le défaut) ; **M** = échanges de
modèle par la passerelle (`policy.failure.modele`, `bloquant` par défaut ;
ICAP et miroir : EX-14.12). « Événement en attente » renvoie à 14.5. Les
codes sont ceux de 4.4 ; `-31010` porte `data.reason` avec la valeur de la
colonne « Raison ». Un échange **bloqué** n'est pas relayé et reçoit `503`
avec le corps d'erreur du format de la route
(`{"type":"error","error":{"type":"noortrace_degrade","message":"noortrace: echange bloque, enregistreur en mode degrade"}}`
pour Messages,
`{"error":{"message":"noortrace: echange bloque, enregistreur en mode degrade","type":"noortrace_degrade","param":null,"code":"noortrace_degrade"}}`
pour Chat Completions et Responses), sans événement : rien n'a atteint le
fournisseur.

| Panne | Détection | E | L | M | Rendu à l'hôte (E) | Raison (`data.reason`) | Journal d'exploitation | Réglage |
|---|---|---|---|---|---|---|---|---|
| **Stockage indisponible** : `write`/`fdatasync` en erreur, disque plein (`ENOSPC`), segment corrompu (EX-12.11), répertoire inaccessible | Erreur à l'écriture ou à la relecture (12.3, 12.4) | bloquant | passant, événement en attente (jusqu'aux bornes de 14.5) | bloquant (`503`) ; avec `failure.modele: "passant"`, relayé, pièces gardées en mémoire et événement en attente | `-31010` | `stockage` | `storage_unavailable` (errno, chemin), `segment_truncated`, `segment_corrupted` | `policy.failure.lecture`, `policy.failure.modele`, `pending_max_*` |
| **Clé indisponible** : signataire en erreur ou hors délai (`sign`, `health`), signature qui ne vérifie pas (EX-11.6), clé révoquée (EX-11.14), message hors borne (EX-11.7) | Appel au signataire | bloquant | **bloquant** (aucun événement, même en attente, ne peut être scellé sans clé ; une lecture passante créerait une attente sans fin) | bloquant (`503`) | `-31010` | `cle` | `signer_unavailable` (type de backend, classe, erreur sans secret) | aucun : « clé indisponible = bloquant pour tout » |
| **Panne après relais** (EX-4.46) : l'une des pannes de ce tableau survient entre l'envoi d'un appel (4.4 pas 9) ou d'une requête de modèle et la durabilité de son événement | Au scellement ou au `fdatasync` | `-31017`, événement complet gardé en attente, scellé à la sortie du mode dégradé à la place d'un événement de reprise | idem | réponse déjà relayée ; événement gardé en attente | `-31017` | raison de la panne | `call_executed_not_durable` (`intent_id`) | — |
| **Serveur d'outils injoignable** : connexion impossible, processus stdio mort, coupure avant réponse | Au relais (4.4 pas 7 à 11) | **bloquant** ; connexion impossible avant le pas 8 : aucune intention, aucun événement ; perte après l'envoi : événement `is_error: true`, pièce `noortrace_jsonrpc_error` `-31014`, `t_reponse` = instant de la perte (EX-4.48) | idem (même règle, pour toute classe) | sans objet | `-31014` | — | `upstream_unreachable` (alias), `child_exited` | `restart.max_attempts`, `restart.backoff_ms` |
| **Délai du serveur d'outils** (EX-4.22) | `timeout_ms` écoulé | événement `is_error: true`, `duration_ms = timeout_ms`, annulation amont, `-31011` | idem | sans objet | `-31011` | — | `upstream_timeout` | `timeout_ms` par outil, serveur, `tools.default_timeout_ms` |
| **Fournisseur de modèle injoignable ou en erreur** (5.7) | Connexion, délais, statut `≥ 400`, flux coupé | sans objet | sans objet | relayé ou échoue, et donne toujours un événement `executee`, `is_error: true` (CT-1 §5.3) | `504` HTTP avec corps `noortrace_timeout`, ou le statut et le corps amont inchangés (EX-5.23, EX-5.24) | — | `provider_error` (statut, `request-id`) | délais de 5.7 ; aucune relance (EX-5.25) |
| **Service d'approbation (CT-3) indisponible** : pas de réponse dans `policy.approval.timeout_ms`, erreur (`non_pret`, `politique_inconnue` après un `charger` et un nouvel essai, `plafond_atteint`, autre), réponse hors des combinaisons d'EX-7.16 | Pas 3 de 4.4, `debutAppel` | **bloquant** (`-31010`) pour tout outil de classe `ecriture` et pour tout outil **susceptible d'approbation** selon la liste du dernier `charger` réussi (EX-7.4, EX-7.15 ; tous les outils tant qu'elle n'a pas été obtenue, et tout nom absent de sa liste `tools`) ; la décision ne peut pas être devinée | passant pour une lecture qui n'est pas susceptible d'approbation, si `policy.failure.approval_service.lecture = "passant"` : relayé avec `policy.decision = "autorise"`, `rule: null`, défaut consigné ; sinon bloquant | sans objet (la politique n'est pas évaluée sur un échange) | `-31010` | `approbation` | `approval_service_unavailable`, `approval_response_invalid` | `policy.approval.timeout_ms`, `policy.failure.approval_service.lecture` |
| **Service d'approbation en défaut** : `retenue` d'un ticket déjà décidé (EX-7.17), vérification de relais en échec (RL-1 à RL-4, EX-7.21) | Pas 6 ou 7 de 4.4, `debutAppel` | **bloquant**, sans événement ni intention ; alerte | idem | sans objet | `-31010` | `approbation` | `identifiant_en_collision`, `approval_relay_refused` (ticket, vérification) | — |
| **Rédaction au-delà de la borne de temps** pour la pièce « arguments » (EX-10.23, opération 1) : taille ou forme des arguments, ou motif nommé coûteux | Pas 4 de 4.4, `debutAppel` | **bloquant** pour un outil de classe `ecriture` ou susceptible d'approbation dont la réponse mène à un relais ou à une `retenue` : ni intention ni événement ; un ticket réservé devient `abandonne` (CT-3 T3) | passant : relayé avec la pièce non rédigeable (EX-8.7) | sans objet (la pièce « requête » non rédigeable n'arrête pas l'échange, EX-10.23) | `-31010` | `redaction` | `redaction_budget_exceeded` (opération, portée, règle), `call_blocked` | `limits.redaction_budget_ms`, `policy.redaction` |
| **Remise refusée** (SG-1 à SG-7, EX-7.5) | Remise de CT-3 | aucune décision scellée ; `acquitter` `refuse` ; le ticket suit CT-3 (T14 à T16) ; alerte | sans objet | sans objet | aucun | — | `approval_remise_refused` (ticket, vérification, raison) | — |
| **Décision d'approbation en attente** (ticket ouvert) | Pas 6 de 4.4 | **retardé** jusqu'à la décision ou `hold_timeout_ms` (mode `retenir`, une requête au plus par ticket, EX-4.50), puis signal `en_attente` ; ou signal `en_attente` immédiat (mode `erreur`) ; une ré-émission en attente ne produit aucun événement | sans objet (une lecture soumise à approbation est traitée comme E) | sans objet | signal d'approbation (résultat `isError: true`, EX-4.49), `state: "en_attente"` | — | `approval_pending` (ticket) | `policy.approval.mode`, `hold_timeout_ms` |
| **Décision remise pendant un mode dégradé** | Remise de CT-3 | la décision n'est pas scellée ; le noyau l'acquitte `temporaire` (EX-7.19), CT-3 la représente ; aucun appel n'est relayé pour ce ticket avant que la décision soit scellée | sans objet | sans objet | signal `en_attente` à une ré-émission | — | `approval_deferred` (ticket) | — |
| **Expiration atteinte pendant un mode dégradé** (EX-9.4) | Minuteur (échéance `request_ts + E`, plus `timeout_ms` pour le noyau seul) | la décision `expire` est scellée à la sortie du mode dégradé, avec la raison fixe de la remise ou du noyau (EX-9.4) | sans objet | sans objet | signal `state: "expire"` à une ré-émission, après scellement | — | `approval_expired_deferred` | `expire_after_ms` de la version de la `retenue` |
| **Ancrage (CT-5) indisponible** : horodateur RFC 3161, calendriers OpenTimestamps | Clôture de période | **jamais bloquant** : la clôture produit le manifeste et sa signature, l'ancre est réessayée par la supervision | idem | idem | aucune | — | `anchor_pending` (période, ancre, tentative) | `anchoring.*` |
| **Registre (CT-4) indisponible** : RPC injoignable, transaction non confirmée, clé non encore inscrite | Clôture de période, inscription de clé | **jamais bloquant** : le manifeste est produit ; `submitPeriod` et l'inscription sont réessayés ; les événements restent valides (CT-1 §15 : le registre est déclaratif sans le contrôle 8) | idem | idem | aucune | — | `registry_pending` | `anchoring.registry.*` |
| **Horloge qui recule** au-delà de `clock.max_backstep_ms` (EX-7.9) | À la lecture de `ts` par l'écrivain | **bloquant pour tout** : l'enregistreur ne peut plus dater honnêtement ; tant que l'horloge murale n'a pas rejoint le `ts` précédent, ou jusqu'à la procédure d'EX-7.13 | **bloquant** | bloquant (`503`) | `-31010` | `horloge` | `clock_backstep` (écart) | `clock.max_backstep_ms`, `clock.max_wait_ms` ; sous le seuil : `ts = max(maintenant, ts précédent)` et `clock_skew` si > `warn_skew_ms` |
| **Horloge qui avance brutalement** (saut en avant, EX-7.13) | Avance murale supérieure à l'avance monotone + `clock.max_forward_ms`, ou écart à l'horloge du magasin de bail | **bloquant pour tout** : aucun `ts` n'est posé dans le futur ; sortie quand l'horloge revient dans la tolérance ou sur confirmation de l'exploitant | **bloquant** | bloquant (`503`) | `-31010` | `horloge` | `clock_forward_jump` (écart) | `clock.max_forward_ms` |
| **Disque presque plein** : espace libre du volume sous `storage.min_free_bytes` (défaut 1 GiB) | Vérification avant ouverture de segment, avant l'écriture de chaque pièce, et toutes les 10 s | bloquant (préventif : mieux vaut refuser que tronquer) | passant, en attente | comme le stockage indisponible | `-31010` | `stockage` | `disk_low` (octets libres) | `storage.min_free_bytes` |
| **Mémoire** : file d'attente d'événements ou tampon de flux au-delà des limites (`limits.*`, 14.5) | Compteurs internes | bloquant quand `pending_max_events`, `pending_max_ms` ou `limits.pending_max_bytes` est atteint (14.5) ; `-31013` pour une taille de message dépassée ou un quota (EX-4.47) | idem | bloquant (`503`) | `-31010` ou `-31013` | `attente` | `pending_limit_reached` | `policy.failure.pending_max_events`, `pending_max_ms`, `limits.*` |
| **Bail perdu** (EX-13.6, EX-13.10) | Vérification avant `fdatasync`, avant signature, et après `fdatasync` | bloquant | **bloquant** (l'instance n'est plus l'écrivain ; une lecture passante ne pourrait jamais être écrite par elle) | bloquant (`503`) | `-31010` (`-31017` après relais) | `bail` | `lease_lost`, `lease_lost_after_write` | `lease.*` |
| **Bail non détenu** (instance passive, 13.4) | Au démarrage et tant que l'acquisition échoue | bloquant | bloquant | bloquant (`503`) | `-31010` | `bail_non_detenu` | `lease_standby` | — |
| **Configuration invalide au démarrage** (15.4) | Validation | le démon **ne démarre pas** : rien n'écoute, l'hôte ne joint personne (préférable à un démon qui relaie sans politique) | idem | idem | aucune (pas de connexion) ; code de retour du processus non nul et rapport sur `stderr` | — | `config_invalid` (erreurs de validation) | — |
| **Configuration invalide au rechargement** (15.5) | Validation | le rechargement est **refusé**, l'ancienne configuration reste en vigueur, le relais continue | idem | idem | aucune | — | `config_reload_rejected` | — |

**EX-14.3** Une panne de la ligne « serveur d'outils injoignable » ou « délai »
pour un appel d'écriture déjà relayé laisse une **incertitude sur l'effet**
(l'appel a pu arriver au serveur) : l'événement le dit (`is_error: true`,
`effects` déclarés, EX-4.23), et l'intention de 12.5 garantit qu'un arrêt de
l'enregistreur au même instant laisserait quand même une trace. L'agent peut
réessayer ; chaque essai est un événement.

**EX-14.4** Deux pannes simultanées se traitent par la plus restrictive :
« clé indisponible » et « bail perdu » bloquent les lectures même quand
`failure.lecture` vaut `passant`.

### 14.3 Ce qui est rendu à l'hôte

**EX-14.5** Les erreurs de cette section sont rendues comme des **erreurs
JSON-RPC** avec les codes et messages fixes de la table de 4.4 (`-31010`,
`-31011`, `-31013`, `-31014`, `-31017`) ; `data` porte les clés nommées dans
la matrice et jamais une donnée du client (ni argument, ni chemin de fichier
du stockage, ni nom d'hôte du magasin de bail). Le texte est ASCII, en
français sans accent, non traduit : les hôtes affichent le message tel quel
et un agent ne doit pas pouvoir en déduire un détail d'exploitation. Côté
passerelle de modèle, les pannes du fournisseur sont des réponses HTTP (5.7),
jamais des erreurs JSON-RPC. L'attente d'une approbation et le refus d'un
ticket, y compris pendant un mode dégradé, sont rendus par le signal
d'approbation, un résultat d'outil (EX-4.49), jamais par une erreur.

**EX-14.6** Une **lecture passante** reçoit sa réponse normale (le `result`
du serveur, EX-4.20) ; rien n'indique à l'hôte que l'événement est en attente
: c'est la santé (`degraded`, section 17) et le journal d'exploitation qui le
disent à l'exploitant.

### 14.4 Ce qui est journalisé

**EX-14.7** Toute entrée ou sortie du mode dégradé produit une ligne du
journal d'exploitation `degraded_enter` / `degraded_exit` avec la raison, et
une variation de la métrique `noortrace_degraded` (17). Les appels bloqués
produisent `call_blocked` (code, raison, alias, nom annoncé, classe, `id`
d'hôte ; jamais les arguments). Les appels passés en attente produisent
`call_passthrough_pending` avec l'identifiant d'attente (14.5). La **chaîne**
ne reçoit rien à l'entrée en mode dégradé : il n'y a pas d'événement
« panne » (CT-1 n'admet que les quatre événements réservés et CT-2 n'en ajoute
aucun) ; ce que la chaîne montre, ce sont les événements de reprise et les
événements en attente écrits plus tard, dont le `ts` dit quand ils ont été
rendus durables (14.5).

### 14.5 Mode dégradé et événements en attente

**EX-14.8** En mode dégradé « stockage » (et dans aucun autre : « clé » et
« bail » bloquent tout), un appel de classe `lecture` dont le comportement est
`passant`, et un échange de modèle si `policy.failure.modele` vaut
`passant`, sont relayés normalement ; dans **tout** mode dégradé, l'appel ou
l'échange déjà relayé quand la panne survient (EX-4.46) suit la même règle.
L'événement est construit (section 7,
sauf `seq`, `ts`, `prev_hash`, `recorder_key_id`, `hash`, `sig`), ses pièces
sont écrites si le stockage des pièces répond encore (sinon elles sont gardées
en mémoire avec l'événement, dans la borne de `limits.piece_max_bytes` par
pièce), et l'événement est ajouté à la **file d'attente** en mémoire et, au
mieux, au fichier `attente/attente-<epoch>.ndjson` (une ligne JCS intégral
`{ "pending_id", "captured_at", "event": <événement partiel>, "pieces":
[sha256…] }`, `fdatasync` tenté sans que son échec change le comportement :
le stockage est précisément ce qui est en panne).

**EX-14.9** Bornes : quand la file dépasse `policy.failure.pending_max_events`
(défaut 10 000), que les pièces gardées en mémoire dépassent
`limits.pending_max_bytes` (défaut 268 435 456), ou que l'événement le plus
ancien attend depuis plus de `policy.failure.pending_max_ms` (défaut
300 000), les lectures et les échanges passants deviennent **bloquants** à
leur tour (`-31010`, `reason: "attente"`) : une attente sans borne n'est plus
une journalisation, et la mémoire du démon reste bornée.

**EX-14.10** À la sortie du mode dégradé (le stockage répond : nouveau segment
ouvert, EX-12.8, EX-12.10), l'écrivain scelle les événements en attente à la
place que leur donne la séquence d'EX-9.8 (après les événements de reprise,
avant tout nouvel événement), dans l'ordre de `captured_at`, chacun avec la
`policy_version` de sa capture, avec `ts = max(captured_at,
ts précédent)` (l'instant de capture, pas celui du scellement : un événement
en attente est une capture retardée, et sa date de capture est connue ; c'est
l'**unique** exception à la règle 7.4 qui lit `ts` à l'instant du scellement),
puis les pièces gardées en mémoire sont écrites. Le journal d'exploitation
reçoit `pending_flushed` (nombre, délai maximal). Un événement en attente
dont la pièce « résultat » a été perdue (mémoire libérée par un redémarrage
sans fichier d'attente) est scellé avec `is_error: true` et une pièce
`{"noortrace_attente":"resultat perdu pendant le mode degrade","pending_id":"…"}`
: la perte est dite dans la chaîne plutôt que tue.

**EX-14.11** Le mode dégradé est **visible** : `GET /healthz` rend `degraded`
avec les raisons, la métrique `noortrace_degraded{reason}` vaut 1, et une
alerte est prescrite (17). La sortie du mode dégradé « clé » exige un
`health()` du signataire réussi et une signature de test vérifiée ; celle du
mode « stockage », l'ouverture et le `fdatasync` d'un nouveau segment ; celle
du mode « bail », une acquisition ; celle du mode « horloge », une horloge
murale ≥ `ts` précédent et dans la tolérance d'avance d'EX-7.13, ou la
procédure d'EX-7.13.

**EX-14.12** **Échanges de modèle en modes ICAP et miroir.** En mode `icap`,
la colonne M s'applique en REQMOD : un échange bloqué reçoit, encapsulée, la
réponse `503` de 14.2 et aucun événement n'est scellé ; une panne qui
survient après le REQMOD (la requête est partie) donne un événement en
attente (EX-4.46), puisque la réponse ne peut plus être bloquée (EX-5.5). En
mode `miroir`, rien n'est bloqué : l'échange observé pendant un mode dégradé
« stockage » est mis en attente ; pendant un mode « clé », « bail » ou
« horloge », il est mis en attente aussi, dans la borne de 14.5, puis perdu
au-delà, chaque perte étant consignée (`exchange_lost`) : un miroir est une
preuve passive, il ne peut pas refuser ce qu'il voit passer.

## 15. Configuration

### 15.1 Document unique

**EX-15.1** L'enregistreur est configuré par **un seul document JSON**,
validé au démarrage contre
`spec/schemas/configuration-enregistreur-v0.schema.json` (`$id`
`https://noortrace.example/schemas/v0/configuration-enregistreur.schema.json`,
JSON Schema 2020-12, `additionalProperties: false` à tous les niveaux, motifs
sur toutes les chaînes contraintes). Le schéma référence par leur `$id`
celui de la politique de rédaction (section 10) et celui de la politique
d'approbation (`politique-approbation-v0`, CT-3 §4), qui décrit
`policy.approval.rules` ; les trois se chargent ensemble (15.6).
Toute clé inconnue est une erreur : une faute de frappe ne devient jamais un
réglage ignoré.

Membres de premier niveau, et correspondance avec les **clés courtes**
employées dans les sections 4 à 9 (le texte de ces sections écrit `tools.prefix`
ou `approval.mode` ; le pointeur JSON RFC 6901 dans le document est celui de
la troisième colonne) :

| Membre | Contenu | Section | Clés courtes des sections 4 à 9 → pointeur |
|---|---|---|---|
| `config_version` | constante `0` | — | — |
| `recorder` | `instance_id`, `org_id`, `journal_id`, `environment` (`production` ou `developpement`) | 3, 11, 13 | — |
| `mcp` | frontal MCP : prise locale des connecteurs stdio, prise TCP des connecteurs (`connector_tcp`, jeton ou mTLS), point de terminaison Streamable HTTP (écoute, chemin, origines, TLS, OAuth, jetons statiques), **connexions d'hôte** (`hosts[]` : `match`, `launched_by`, `scope`, `on_behalf_of`, `accept_declared_delegation`, `allowed_on_behalf_of`, `tool_name_template`, `tool_name_sanitize`, `prompt_version_name`, `host_group`, `quota`, `alias`), délais `discover_timeout_ms`, `drain_timeout_ms`, `child_exit_timeout_ms` | 4.2, 4.7, 4.8, 7.2 | `discover_timeout_ms` → `/mcp/discover_timeout_ms` ; `drain_timeout_ms`, `child_exit_timeout_ms` → idem ; `tool_name_template`, `tool_name_sanitize` (EX-5.22), `host_group`, `quota` (EX-4.47) → `/mcp/hosts/<i>/…` |
| `tools` | `prefix`, `page_size`, `default_ttl_ms`, `default_timeout_ms`, `definition_in_context`, `list_in_context`, `list_changed_min_interval_ms` | 4.3, 4.4, 7.2 | `tools.*` → `/tools/*` |
| `limits` | `request_max_bytes`, `response_max_bytes`, `model_request_max_bytes`, `model_response_max_bytes`, `piece_max_bytes`, `json_max_depth`, `json_max_members`, `line_max_bytes`, `tools_list_max_pages`, `tools_list_max_items`, `pending_max_bytes`, `redaction_budget_ms` | 4.3, 4.4, 4.7, 5.3, 8, 10, 14 | `limits.*` → `/limits/*` |
| `relay` | `resources`, `prompts`, `completions`, `server_requests.{sampling, elicitation, roots}` | 4.5, 4.6 | `relay.*` → `/relay/*` |
| `restart` | `max_attempts`, `backoff_ms` | 4.7.1 | `restart.*` → `/restart/*` |
| `auth` | `strip_headers` | 4.8 | `auth.strip_headers` → `/auth/strip_headers` |
| `clock` | `max_backstep_ms`, `warn_skew_ms`, `max_forward_ms`, `max_wait_ms` | 7.4, 14 | `clock.*` → `/clock/*` |
| `model` | frontal modèle : `mode`, `listen`, `tls`, **connexions d'hôte** de la passerelle, de l'ICAP et du miroir (`hosts[]`, même forme que `mcp.hosts`), `static_tokens`, `forward_headers`, `strip_headers`, `prompt_in_request` (`reference` ou `inline`, EX-8.5), `prompt_system` (`redige` ou `named`, EX-8.6), délais, `correlation_window_ms`, `icap` (`listen`, `tls_listen`, `client_ca`, `allowed_sources`, `client_address_header`), `mirror` ; les **routes** sont dans `policy.model` | 5, 8 | `model.*` → `/model/*` ; `connect_timeout_ms`, `first_byte_timeout_ms`, `idle_timeout_ms` → `/model/…` ; routes, `credentials`, `provider_label`, `passthrough` → `/policy/model/routes/<i>/…` |
| `sdk` | `enabled`, `socket`, `tcp_listen` (jeton ou mTLS), `hosts[]` (avec `alias`, EX-6.6) | 6 | — |
| `signer` | `class`, `key_id`, `backend`, `verify_after_sign`, `max_message_bytes`, `timeout_ms`, `health_interval_ms`, `rotation` | 11 | `signer.*` → `/signer/*` |
| `storage` | `root`, `segment_max_bytes`, `fsync`, `seal` (`append_only_attribute`, `worm`), `retention`, `vault`, `relay_mac_key` (clé du MAC de relais, EX-7.22) | 7.5, 10.7, 12 | `storage.*` → `/storage/*` |
| `lease` | `store` (`file`, `postgresql`, `etcd`), `ttl_ms`, `renew_ms`, `acquire_wait_ms`, `fencing` (EX-13.10) | 13 | `lease.*` → `/lease/*` |
| `anchoring` | raccords CT-4 (`registry` : `rpc_url`, `chain_key`, `next_chain_key`, EX-11.19) et CT-5 (`rfc3161`, `opentimestamps`), jamais bloquants | 11, 14 | — |
| `supervision` | `health_listen`, `metrics`, `ops_log` (`path`, `level`, `rotate_max_bytes`, `keep_files`, `child_stderr`, `child_stderr_max_bytes`, `child_stderr_lines_per_second`) | 9.2, 17 | `logging.rotate_bytes` → `/supervision/ops_log/rotate_max_bytes` ; `logging.keep_files` → `/supervision/ops_log/keep_files` ; `logging.child_stderr_max_bytes` → `/supervision/ops_log/child_stderr_max_bytes` |
| `policy` | **l'ensemble de politique** (10.6) : `version`, `approval` (`rules`, document `politique-approbation-v0` de CT-3 §4, que CT-2 valide sans l'évaluer, EX-15.4 ; `mode`, requis, `erreur` dans la configuration de référence, CT-3 EX-11.1 ; `hold_timeout_ms`, `expire_after_ms`, `timeout_ms`, `service`), `redaction` (document de la section 10), `servers` (carte des serveurs d'outils par alias : `transport` avec, en stdio, `user` et `integrity`, et en HTTP les épinglages OAuth, `protocol`, `class_default`, `timeout_ms`, `tools.<nom>.{class, timeout_ms, effects, failure}`, `uri_prefixes`, `relay`), `model` (`routes` : `path`, `format`, `upstream`, `provider_label`, `credentials`, `secret`, `auth_header`, `passthrough`), `failure` (dont `modele`) | 4.3, 4.4, 5.1, 7.2, 10, 14 | `approval.mode`, `approval.hold_timeout_ms`, `approval.expire_after_ms` → `/policy/approval/…` ; `policy.timeout_ms` → `/policy/approval/timeout_ms` ; `resources.uri_prefixes` → `/policy/servers/<alias>/uri_prefixes` ; `protocol` d'un serveur → `/policy/servers/<alias>/protocol` ; `timeout_ms` par outil → `/policy/servers/<alias>/tools/<nom>/timeout_ms` ; `effects` (gabarit) → `…/tools/<nom>/effects` ; `relay.server_requests` par serveur → `/policy/servers/<alias>/relay` ; `passthrough` → `/policy/model/routes/<i>/passthrough` |

**EX-15.2** Les membres hors `policy` sont la **configuration d'exploitation**
: un changement y exige un redémarrage du démon et ne produit aucun événement
(il est consigné). Le membre `policy` est l'**ensemble de politique** : un
changement y est appliqué par rechargement (15.5) et produit l'événement
`noortrace.journal.politique` (EX-10.21). La carte des serveurs d'outils est
dans `policy` parce que remplacer un serveur ou reclasser un outil change ce
que le journal prouve ; l'adresse d'écoute ou le chemin du stockage ne le
changent pas.

### 15.2 Références de secrets

**EX-15.3** Aucun secret n'est écrit dans le document. Partout où un secret est
attendu (jetons statiques, PIN PKCS#11, jeton Vault, phrase de passe de classe
D, clés de fournisseurs de modèle, en-têtes et variables d'environnement des
serveurs d'outils, DSN PostgreSQL, identifiants WORM, compte du registre, clé
du coffre, clé de pseudonymisation, clé du MAC de relais), le document porte
une **référence de secret**, objet à une clé d'emplacement (`env`, `file` ou
`vault`) et, quand la valeur doit devenir des octets (clé de pseudonymisation,
EX-10.12, et clé du MAC de relais, EX-7.22, où elle est obligatoire ; clé du
coffre ; graines), une clé `encoding` : `"hex"` (chiffres hexadécimaux, préfixe
`0x` facultatif, longueur paire), `"base64"` (RFC 4648 § 4, avec remplissage)
ou `"utf8"` (les octets UTF-8 de la chaîne) ; une longueur minimale s'entend
toujours en octets **après décodage**. Formes :

| Forme | Résolution | Règles |
|---|---|---|
| `{ "env": "NOM" }` | Variable d'environnement du démon, nom `^[A-Z][A-Z0-9_]{0,127}$` | Lue au démarrage ; absente → erreur de validation ; la variable n'est jamais transmise aux processus enfants (serveurs stdio) sauf si une entrée `env` d'un serveur la désigne explicitement |
| `{ "file": "/chemin" }` | Contenu du fichier (octets, sans retrait du saut de ligne final : c'est au client d'écrire le fichier sans) | Le fichier DOIT appartenir à l'utilisateur du démon et n'être lisible que par lui (`0400` ou `0600`) ; sinon erreur. Forme recommandée avec les secrets montés par un orchestrateur (`/run/secrets/…`) |
| `{ "vault": { "path": "kv/data/noortrace/…", "field": "…" } }` | Lecture KV dans Vault ou OpenBao, à l'adresse et avec le jeton de `signer.backend` quand il est de type `vault-transit`/`openbao-transit`, sinon avec `VAULT_ADDR` et `VAULT_TOKEN` de l'environnement | Lue au démarrage ; une relecture périodique n'est pas dans la version 0 |

Les valeurs résolues vivent en mémoire du démon, ne sont jamais écrites (pas
même dans le journal d'exploitation en niveau `debug`), et sont effacées à
l'arrêt. La validation (15.4) refuse une chaîne qui ressemble à un secret là
où une référence est attendue (le schéma l'impose par la forme objet) et
avertit sur une valeur littérale dans `env` d'un serveur stdio dont le nom
contient `KEY`, `TOKEN`, `SECRET`, `PASSWORD` ou `PIN`.

### 15.3 Exemple complet

Le document ci-dessous valide contre le schéma (vérifié avec `npx --yes
ajv-cli@5 validate --spec=draft2020 --strict=true -s
configuration-enregistreur-v0.schema.json -r
politique-redaction-v0.schema.json -r politique-approbation-v0.schema.json`,
aucun avertissement) ;
il décrit l'enregistreur d'un journal `journal-sinistres` (`journal_id` des
vecteurs CT-1) avec deux serveurs d'outils (un ERP en Streamable HTTP, un
serveur de fichiers stdio sous un utilisateur propre et un bac à sable
`bwrap`, épinglé par l'empreinte de son exécutable), la passerelle de modèle
en mode `propre` pour trois routes, une clé de classe A par le module
PKCS#11 du fabricant d'un module matériel, une clé de chaîne en enveloppe, un
bail PostgreSQL avec détachement du volume à la bascule et une copie WORM S3
en mode Compliance. Les chemins du module PKCS#11 et du serveur de fichiers,
l'empreinte de ce dernier et l'adresse de la clé de chaîne sont illustratifs ;
la ligne de commande `bwrap` (qui part d'un espace de montage vide :
`/usr`, les liens de bibliothèques, `/proc` et `/dev` y sont montés, et le
seul répertoire inscriptible est celui où le serveur écrit) est à tester en
phase 2. Sa politique d'approbation (`policy.approval.rules`) est un
document `politique-approbation-v0` qui passe les vérifications de CT-3
EX-4.2 et EX-8.2 : mode d'attente `erreur` (CT-3 EX-11.1) ; jeu
d'approbateurs lu au registre, puisque `recorder.environment` vaut
`production`, où un jeu `statique` est refusé (CT-3 EX-8.2) ; `chain_id`,
`registry` et `set` repris de l'exemple de CT-3 §4.3 ; noms d'outils aux
préfixes `sap__` et `fichiers__` ; demandeur `agent-sinistres`
(l'utilisateur du connecteur, `${peer_user}`), détenteur de l'adresse du
compte Hardhat 3, exclu de l'approbation de ses propres demandes. Les outils
susceptibles d'approbation de cet exemple (`CANDIDATS`, CT-3 EX-4.11) sont
`fichiers__write_file` et `sap__payments.create`. Son membre `policy` est
celui dont l'empreinte figure en 10.6.

<!-- schema: configuration-enregistreur -->
```json
{
  "config_version": 0,
  "recorder": {
    "instance_id": "enregistreur-sinistres-1",
    "org_id": "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
    "journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
    "environment": "production"
  },
  "mcp": {
    "enabled": true,
    "socket": "/run/noortrace/mcp.sock",
    "connector_tcp": null,
    "http": {
      "listen": "127.0.0.1:8300",
      "path": "/mcp",
      "allowed_origins": [],
      "tls": null,
      "oauth": null,
      "static_tokens": [{"id": "cursor-postes", "token": {"env": "NOORTRACE_TOKEN_CURSOR"}}]
    },
    "hosts": [
      {
        "id": "agent-sinistres-stdio",
        "match": { "peer_user": "agent-sinistres" },
        "launched_by": "${peer_user}",
        "scope": "sinistres:lecture,paiement",
        "on_behalf_of": "service-sinistres",
        "accept_declared_delegation": true,
        "allowed_on_behalf_of": ["service-sinistres"],
        "tool_name_template": "{tool_announced}",
        "tool_name_sanitize": false,
        "prompt_version_name": null,
        "host_group": "agent-sinistres",
        "quota": { "max_concurrent": 32, "piece_bytes_per_minute": 268435456, "received_bytes_per_minute": 268435456, "redaction_ms_per_minute": 30000 },
        "alias": null
      },
      {
        "id": "cursor-postes",
        "match": { "static_token": "cursor-postes" },
        "launched_by": "poste-cursor",
        "scope": "sinistres:lecture",
        "on_behalf_of": null,
        "accept_declared_delegation": false,
        "allowed_on_behalf_of": [],
        "tool_name_template": "{tool_announced}",
        "tool_name_sanitize": false,
        "prompt_version_name": null,
        "host_group": "cursor-postes",
        "quota": { "max_concurrent": 32, "piece_bytes_per_minute": 268435456, "received_bytes_per_minute": 268435456, "redaction_ms_per_minute": 30000 },
        "alias": null
      }
    ],
    "discover_timeout_ms": 3000,
    "drain_timeout_ms": 10000,
    "child_exit_timeout_ms": 5000
  },
  "tools": {
    "prefix": true,
    "page_size": 100,
    "default_ttl_ms": 300000,
    "default_timeout_ms": 120000,
    "definition_in_context": true,
    "list_in_context": true,
    "list_changed_min_interval_ms": 1000
  },
  "limits": {
    "request_max_bytes": 16777216,
    "response_max_bytes": 16777216,
    "model_request_max_bytes": 33554432,
    "model_response_max_bytes": 33554432,
    "piece_max_bytes": 67108864,
    "json_max_depth": 128,
    "json_max_members": 100000,
    "line_max_bytes": 16842752,
    "tools_list_max_pages": 100,
    "tools_list_max_items": 10000,
    "pending_max_bytes": 268435456,
    "redaction_budget_ms": 1000
  },
  "relay": {
    "resources": false,
    "prompts": false,
    "completions": false,
    "server_requests": { "sampling": false, "elicitation": false, "roots": false }
  },
  "restart": { "max_attempts": 3, "backoff_ms": 1000 },
  "auth": { "strip_headers": ["X-Forwarded-Authorization"] },
  "clock": {
    "max_backstep_ms": 5000,
    "warn_skew_ms": 1000,
    "max_forward_ms": 60000,
    "max_wait_ms": 3600000
  },
  "model": {
    "mode": "passerelle",
    "listen": "127.0.0.1:8400",
    "tls": null,
    "hosts": [
      {
        "id": "agent-sinistres-passerelle",
        "match": { "static_token": "agent-sinistres-passerelle" },
        "launched_by": "agent-sinistres",
        "scope": "sinistres:lecture,paiement",
        "on_behalf_of": "service-sinistres",
        "accept_declared_delegation": true,
        "allowed_on_behalf_of": ["service-sinistres"],
        "tool_name_template": "{tool_announced}",
        "tool_name_sanitize": false,
        "prompt_version_name": null,
        "host_group": "agent-sinistres",
        "quota": { "max_concurrent": 32, "piece_bytes_per_minute": 268435456, "received_bytes_per_minute": 268435456, "redaction_ms_per_minute": 30000 },
        "alias": null
      }
    ],
    "static_tokens": [
      { "id": "agent-sinistres-passerelle", "token": {"env": "NOORTRACE_TOKEN_PASSERELLE"} }
    ],
    "forward_headers": [],
    "strip_headers": [],
    "prompt_in_request": "reference",
    "prompt_system": "redige",
    "connect_timeout_ms": 10000,
    "first_byte_timeout_ms": 120000,
    "idle_timeout_ms": 120000,
    "correlation_window_ms": 600000,
    "icap": null,
    "mirror": null
  },
  "sdk": { "enabled": false, "socket": null, "tcp_listen": null, "hosts": [] },
  "signer": {
    "class": "A",
    "key_id": "rec-sinistres-2026-01",
    "backend": {
      "type": "pkcs11",
      "module": "/opt/hsm-fabricant/lib/libpkcs11-fabricant.so",
      "token_label": "noortrace",
      "key_label": "rec-sinistres-2026-01",
      "pin": { "env": "NOORTRACE_PKCS11_PIN" },
      "mechanism": "CKM_EDDSA"
    },
    "verify_after_sign": true,
    "max_message_bytes": null,
    "timeout_ms": 5000,
    "health_interval_ms": 10000,
    "rotation": { "planned_every_days": 365, "next_key_id": null }
  },
  "storage": {
    "root": "/var/lib/noortrace",
    "segment_max_bytes": 268435456,
    "min_free_bytes": 1073741824,
    "fsync": { "group_max_events": 64, "group_max_wait_ms": 5 },
    "seal": {
      "append_only_attribute": true,
      "worm": {
        "type": "s3-object-lock",
        "bucket": "noortrace-sinistres-worm",
        "prefix": "journal-sinistres/",
        "mode": "compliance",
        "retain_days": 4018,
        "credentials": { "file": "/run/secrets/sos-worm" }
      }
    },
    "retention": { "events_years": 11, "pieces_days": null },
    "vault": { "enabled": false, "path": null, "key": null },
    "relay_mac_key": { "file": "/run/secrets/cle-mac-relais", "encoding": "hex" }
  },
  "lease": {
    "store": {
      "type": "postgresql",
      "dsn": { "env": "NOORTRACE_LEASE_DSN" },
      "table": "noortrace_lease"
    },
    "ttl_ms": 10000,
    "renew_ms": 3000,
    "acquire_wait_ms": 30000,
    "fencing": "detachement"
  },
  "anchoring": {
    "registry": {
      "enabled": true,
      "rpc_url": "https://registre-dev.example/rpc",
      "chain_key": {
        "class": "C",
        "address": "0x1111111111111111111111111111111111111111",
        "secret": { "file": "/run/secrets/cle-chaine-enveloppe" },
        "service_url": null
      },
      "next_chain_key": null
    },
    "rfc3161": { "enabled": false, "url": null },
    "opentimestamps": {
      "enabled": true,
      "calendars": ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
    }
  },
  "supervision": {
    "health_listen": "127.0.0.1:8500",
    "metrics": true,
    "ops_log": {
      "path": "/var/log/noortrace/exploitation.ndjson",
      "level": "info",
      "rotate_max_bytes": 104857600,
      "keep_files": 30,
      "child_stderr_max_bytes": 4096,
      "child_stderr": "empreinte",
      "child_stderr_lines_per_second": 20
    }
  },
  "policy": {
    "version": "2026-11-01",
    "approval": {
      "rules": {
        "version": 0,
        "default": {
          "name": "defaut : revue",
          "description": "Tout appel qu'aucune règle ne couvre est soumis aux approbateurs.",
          "level": "revue",
          "decision": null,
          "contest_ms": 0
        },
        "rules": [
          {
            "name": "lectures autorisees",
            "description": null,
            "tools": ["sap__claims.get", "fichiers__list_directory", "fichiers__read_file"],
            "when": null,
            "level": "automatique",
            "decision": "autorise",
            "window": null,
            "contest_ms": null
          },
          {
            "name": "paiement hors CHF",
            "description": "Les paiements de sinistre se font en francs suisses.",
            "tools": ["sap__payments.create"],
            "when": { "none": [{ "path": "/arguments/currency", "op": "egal", "value": "CHF" }] },
            "level": "automatique",
            "decision": "refuse",
            "window": null,
            "contest_ms": null
          },
          {
            "name": "paiement <= 5000 CHF",
            "description": null,
            "tools": ["sap__payments.create"],
            "when": {
              "all": [
                { "path": "/arguments/currency", "op": "egal", "value": "CHF" },
                { "path": "/arguments/amount", "op": "inferieur_ou_egal", "value": "5000" }
              ]
            },
            "level": "automatique",
            "decision": "autorise",
            "window": null,
            "contest_ms": null
          },
          {
            "name": "paiement > 5000 CHF",
            "description": "Chaque paiement est approuvé au seuil du jeu d'approbateurs.",
            "tools": ["sap__payments.create"],
            "when": {
              "all": [
                { "path": "/arguments/currency", "op": "egal", "value": "CHF" },
                { "path": "/arguments/amount", "op": "strictement_superieur", "value": "5000" }
              ]
            },
            "level": "revue",
            "decision": null,
            "window": null,
            "contest_ms": 0
          }
        ],
        "approver_set": {
          "source": "registre",
          "chain_id": 2124,
          "registry": "0x172076e0166d1f9cc711c77adf8488051744980c",
          "set": "0x35312352c0065a3fc46ce14dba05df3fcee9fbc2",
          "members": null,
          "threshold": null
        },
        "separation": {
          "self_approval": "interdite",
          "identities": [
            { "launched_by": "agent-sinistres", "addresses": ["0x90f79bf6eb2c4f870365e785982e1f101e93b906"] },
            { "launched_by": "poste-cursor", "addresses": ["0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"] }
          ]
        }
      },
      "mode": "erreur",
      "hold_timeout_ms": 50000,
      "expire_after_ms": 3600000,
      "timeout_ms": 2000,
      "service": { "url": null, "socket": "/run/noortrace/approbation.sock", "token": null, "peer_user": "noortrace-approbation" }
    },
    "redaction": {
      "version": 0,
      "name": "pii-v1",
      "description": "Politique de redaction publiee avec CT-2 : identifiants personnels et financiers courants (IBAN, numero AVS, adresse electronique, numero de telephone international, numero de carte de paiement) remplaces par un jeton type dans toutes les pieces.",
      "pseudonym_key": null,
      "named_patterns": {
        "numero-sinistre": {
          "pattern": "\\b20[0-9]{2}-[0-9]{5}\\b",
          "description": "Numero de dossier de sinistre AAAA-NNNNN de l'assureur de demonstration ; n'est pas une donnee personnelle, declare ici pour montrer une regex nommee et laisse hors de toute regle."
        }
      },
      "rules": [
        {
          "id": "identifiants-arguments-resultat",
          "description": "Arguments et resultats de tout appel d'outil : tout texte.",
          "scopes": ["arguments", "resultat"],
          "tools": "*",
          "detectors": [
            { "type": "iban" },
            { "type": "avs" },
            { "type": "carte" },
            { "type": "email" },
            { "type": "telephone" }
          ],
          "action": { "kind": "remplacer" }
        },
        {
          "id": "identifiants-modele",
          "description": "Requetes, reponses et prompt systeme des echanges de modele : tout texte.",
          "scopes": ["requete", "reponse", "prompt_systeme"],
          "tools": "*",
          "detectors": [
            { "type": "iban" },
            { "type": "avs" },
            { "type": "carte" },
            { "type": "email" },
            { "type": "telephone" }
          ],
          "action": { "kind": "remplacer" }
        },
        {
          "id": "identifiants-contexte",
          "description": "Documents de contexte remis par le SDK : tout texte.",
          "scopes": ["contexte"],
          "tools": "*",
          "detectors": [
            { "type": "iban" },
            { "type": "avs" },
            { "type": "carte" },
            { "type": "email" },
            { "type": "telephone" }
          ],
          "action": { "kind": "remplacer" }
        }
      ]
    },
    "servers": {
      "sap": {
        "transport": {
          "type": "http",
          "url": "https://sap-mcp.interne.example/mcp",
          "headers": { "Authorization": {"env": "NOORTRACE_SAP_BEARER"} },
          "oauth": null,
          "tls": null
        },
        "protocol": "auto",
        "class_default": "ecriture",
        "timeout_ms": 60000,
        "tools": {
          "payments.create": {
            "class": "ecriture",
            "timeout_ms": null,
            "effects": [
              {
                "system": "SAP",
                "action": "ecriture",
                "object": "/result/structuredContent/payment_id",
                "amount": "/arguments/amount",
                "currency": "/arguments/currency"
              }
            ],
            "failure": null
          },
          "claims.get": {
            "class": "lecture",
            "timeout_ms": null,
            "effects": null,
            "failure": "passant"
          }
        },
        "uri_prefixes": [],
        "relay": null
      },
      "fichiers": {
        "transport": {
          "type": "stdio",
          "command": ["/opt/mcp/server-filesystem/bin/server-filesystem", "/srv/sinistres/pieces"],
          "cwd": "/srv/sinistres",
          "env": {},
          "sandbox": [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/bin",
            "/bin",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/opt/mcp/server-filesystem",
            "/opt/mcp/server-filesystem",
            "--bind",
            "/srv/sinistres/pieces",
            "/srv/sinistres/pieces"
          ],
          "user": "mcp-fichiers",
          "integrity": {
            "sha256": "0x9d5f0e3b1c7a4e2f8b6d0c9a7e5f3b1d2c4e6a8b0d2f4e6a8c0b2d4f6e8a0c2e"
          }
        },
        "protocol": "legacy",
        "class_default": "ecriture",
        "timeout_ms": null,
        "tools": {
          "list_directory": {
            "class": "lecture",
            "timeout_ms": null,
            "effects": null,
            "failure": null
          },
          "read_file": { "class": "lecture", "timeout_ms": null, "effects": null, "failure": null },
          "write_file": {
            "class": "ecriture",
            "timeout_ms": null,
            "effects": null,
            "failure": null
          }
        },
        "uri_prefixes": ["file:///srv/sinistres/"],
        "relay": { "sampling": false, "elicitation": false, "roots": false }
      }
    },
    "model": {
      "routes": [
        {
          "path": "/v1/messages",
          "format": "anthropic-messages",
          "upstream": "https://api.anthropic.com",
          "provider_label": "anthropic",
          "credentials": "propre",
          "secret": { "file": "/run/secrets/cle-anthropic" },
          "auth_header": "x-api-key",
          "passthrough": [
            { "method": "POST", "path": "/v1/messages/count_tokens" },
            { "method": "GET", "path": "/v1/models" }
          ]
        },
        {
          "path": "/v1/chat/completions",
          "format": "openai-chat",
          "upstream": "https://api.openai.com",
          "provider_label": "openai",
          "credentials": "propre",
          "secret": { "file": "/run/secrets/cle-openai" },
          "auth_header": "authorization-bearer",
          "passthrough": []
        },
        {
          "path": "/v1/responses",
          "format": "openai-responses",
          "upstream": "https://api.openai.com",
          "provider_label": "openai",
          "credentials": "propre",
          "secret": { "file": "/run/secrets/cle-openai" },
          "auth_header": "authorization-bearer",
          "passthrough": []
        }
      ]
    },
    "failure": {
      "ecriture": "bloquant",
      "lecture": "passant",
      "modele": "bloquant",
      "approval_service": { "ecriture": "bloquant", "lecture": "passant" },
      "pending_max_events": 10000,
      "pending_max_ms": 300000
    }
  }
}
```

Le demandeur fixe `poste-cursor`, jeton partagé des postes Cursor, a son
entrée dans `separation.identities` : les adresses déclarées des personnes
qui partagent ce jeton (ici une adresse illustrative), qui ne peuvent pas
approuver ses demandes ; sans elle, la séparation des tâches ne serait pas
vérifiable pour les paiements demandés depuis ces postes, et la commande de
validation (15.6) l'avertirait (CT-3 EX-4.14, cinquième point, EX-10.5). Les
avertissements des contrôles de démarrage sont donc vides pour cet exemple.
Chaque connexion d'hôte porte les quatre quotas d'EX-4.47.

### 15.4 Validation au démarrage

**EX-15.4** Le démon DOIT, dans cet ordre, et s'arrêter à la première erreur
avec un rapport sur `stderr` (une ligne par erreur : pointeur JSON, règle,
valeur fautive sauf pour les secrets) et un code de retour `2` :

1. analyser le document en JSON strict (clés uniques) ;
2. valider contre le schéma (toutes les erreurs sont rapportées, pas
   seulement la première) ;
3. vérifier les règles que le schéma n'exprime pas :
   - cohérence `signer.class` / `signer.backend.type` (A ↔ `pkcs11` ; B ↔
     `vault-transit`, `openbao-transit`, `aws-kms`, `gcp-kms` ; C ↔
     `envelope` ; D ↔ `file`) ; `environment: "production"` refuse D
     (EX-11.8) et le mode local du connecteur (EX-3.3) ;
   - alias de serveurs uniques, aucun alias `noortrace` (EX-4.9) ;
     `tools.prefix: false` seulement avec un seul serveur (EX-4.10) ;
   - `match.static_token` désigne un `id` existant de `mcp.http.static_tokens`
     (entrées de `mcp.hosts`) ou de `model.static_tokens` ou
     `mcp.http.static_tokens` (entrées de `model.hosts`) ; chaque `id` de jeton
     est référencé par au plus une connexion **par frontal** ; au moins une
     connexion d'hôte par frontal actif (EX-7.3) ; `match.source_addresses`
     seulement dans `model.hosts` en modes `icap` et `miroir` ; `alias` non
     nul et distinct de tout alias de serveur dans `sdk.hosts`, nul ailleurs
     (EX-6.6) ; `allowed_on_behalf_of` non vide seulement avec
     `accept_declared_delegation: true` ;
   - noms annoncés : aucune collision après application du gabarit et de la
     normalisation de chaque connexion d'hôte (EX-4.11) ;
   - routes du frontal modèle (`policy.model.routes`) : chemins exacts
     distincts, aucun couple (méthode, chemin) de `passthrough` égal à une
     route ou présent deux fois, `secret` non nul si `credentials: "propre"` ;
     `listen` non nul en mode `passerelle` ; `icap` non nul en mode `icap` ;
     `mirror` non nul en mode `miroir` ;
   - politique de rédaction : règles d'EX-10.6, sous-ensemble commun des
     motifs nommés et ses règles de structure et de taille, contrôle des
     jetons de chaque motif nommé sous la borne de temps
     `limits.redaction_budget_ms` (EX-10.23, opération 4 : un motif trop
     coûteux sur les jetons est refusé), `encoding` de `pseudonym_key` et
     longueur d'au moins 32 octets après décodage (vérifiée au pas 4) ;
   - gabarits d'effets : pointeurs bien formés, `action` et `object`
     cohérents ; `currency` littéral de trois lettres majuscules ou pointeur ;
     `extract` dans le sous-ensemble commun d'EX-10.6, règles de structure et
     de taille comprises ; avertissement pour un pointeur qui désigne un
     chemin visé par une règle `champ` (EX-7.6) ;
   - politique d'approbation (`policy.approval.rules`) : les vérifications
     d'EX-4.2 de CT-3 (schéma `politique-approbation-v0`, puis les points 1
     à 7 qu'il n'exprime pas) et celles d'EX-8.2 de CT-3, avec
     `recorder.environment` et `/policy/approval/expire_after_ms` ; un
     document refusé l'est avant d'être annoncé dans la chaîne (pas 6),
     plutôt qu'annoncé puis refusé par le service, ce qui bloquerait tout
     outil susceptible d'approbation (CT-3 EX-4.2). Adoptée par la version
     0.3 (proposition de CT-3 §15.2) ; les avertissements d'EX-4.14 de CT-3
     qui ne dépendent pas de la liste des outils annoncés, avec les
     `launched_by` fixes (EX-7.15), sont rapportés sans refuser ; au pas 3,
     aucun serveur d'outils n'est joint, et l'avertissement d'un sélecteur
     qui ne désigne aucun outil est écrit par le service dans son journal, à
     `charger` (EX-7.15) ;
   - `policy.approval.mode` : avertissement quand il vaut `retenir` (CT-3
     EX-11.1), qui rappelle la condition d'EX-4.50 sur `hold_timeout_ms` et
     le délai des hôtes raccordés, que la configuration ne connaît pas ;
   - en `environment: "production"` : chaque serveur stdio a un `user`
     distinct de celui du démon et un `integrity` (EX-3.5) ; chaque serveur
     HTTP à OAuth a `issuer` et `resource_metadata_url` (EX-4.40) ; toute
     prise TCP (`mcp.connector_tcp`, `sdk.tcp_listen`) a une authentification
     du client (EX-4.39) ; le mode `icap` a `client_ca` ou `allowed_sources`
     (EX-5.3) ; `anchoring.registry.chain_key` n'est pas de classe D
     (EX-11.19) ; `lease.fencing` est non nul avec un magasin `postgresql`
     ou `etcd` (EX-13.10) ; le service d'approbation embarqué de
     démonstration est refusé (EX-18.8) ; avertissement si
     `signer.backend.module` désigne un module PKCS#11 logiciel connu
     (`libsofthsm2.so`), qui vaut la classe D (11.2) bien qu'il soit déclaré en
     classe A ;
   - `lease.renew_ms < lease.ttl_ms / 2` ;
   - `storage.retention.events_years ≥ 10` et, si `worm` est configuré,
     `retain_days ≥ 365 × events_years` (avertissement si inférieur à
     365 × (events_years + 1), 12.7) ;
   - `signer.max_message_bytes` : avertissement si la borne peut être
     dépassée par une approbation de `threshold.size` signatures (EX-11.7) :
     pour un jeu `statique`, `approver_set.threshold.size` de
     `policy.approval.rules` ; pour un jeu `registre`, la taille n'est connue
     qu'à la lecture du jeu, et le noyau fait le même contrôle, à titre
     d'avertissement consigné, sur l'`approver_set` de la première réponse
     `nouveau` de chaque version de politique. Une remise porte exactement le
     seuil effectif de signatures (CT-3 EX-7.28), qui ne dépasse pas le plus
     grand `threshold.size` lu : l'estimation par `size` est prudente ;
   - `policy.failure` : avertissement nominatif pour chaque outil
     `ecriture` à `failure: "passant"` (EX-14.2) ;
4. résoudre toutes les références de secrets (15.2) ; échec → erreur ;
   `pseudonym_key` et `storage.relay_mac_key` d'au moins 32 octets après
   décodage (EX-10.12, EX-7.22) ;
5. ouvrir le stockage (12.4), acquérir ou attendre le bail (13), lire la clé
   publique du signataire (`public_key`, 11.5) et produire une signature de
   test vérifiée (EX-11.6) ;
6. calculer `policy_sha256` du membre `policy` (EX-10.21) et le comparer à
   celui du **dernier événement `noortrace.journal.politique`** du journal :
   s'il diffère (politique changée pendant l'arrêt) ou si le journal est vide
   ou n'a jamais eu d'événement de politique, écrire l'événement de politique
   à la place que lui donne EX-9.8 (après les événements de reprise et en
   attente, avant tout nouvel appel ; en tête du journal s'il est vide) ; si
   `policy.version` n'a pas changé alors que l'empreinte a changé, refuser le
   démarrage (EX-10.21) ; relire les fichiers des approbations (EX-12.23) ;
   envoyer `charger` au service d'approbation pour obtenir la liste des
   outils susceptibles d'approbation (EX-7.4, EX-7.15), sans attendre sa
   réponse pour ouvrir les frontaux (tout outil est susceptible tant
   qu'elle manque), puis `ouvrir` pour les tickets sans décision (EX-7.18),
   `consommer` à renvoyer (EX-7.20) et `decisions` (EX-7.19) ;
7. consigner `startup` dans le journal d'exploitation avec le `sha256` des
   octets du document de configuration tel que lu (section 18), la classe de
   garde, le `recorder_key_id`, les alias de serveurs, les commandes exactes
   des serveurs stdio (EX-3.4), le mode du frontal modèle ; puis ouvrir les
   frontaux.

### 15.5 Rechargement

**EX-15.5** Sur `SIGHUP` ou la commande `noortrace-ctl reload`, le démon
relit le document, exécute les pas 1 à 4 de 15.4 sur le nouveau document et,
en cas d'erreur, **refuse** le rechargement (l'ancien reste en vigueur,
`config_reload_rejected`). En mode dégradé (quel qu'il soit), l'événement de
politique ne peut pas être scellé : le rechargement est **refusé** avec la
raison `mode_degrade`, et les lectures passantes continuent sous la version
annoncée (EX-9.1, EX-9.2). Sinon : si un membre **hors** `policy` a changé,
le rechargement est refusé avec le message « redémarrage requis » et la liste
des pointeurs changés ; si seul `policy` a changé, `policy.version` DOIT
différer de la version en vigueur (sinon refus), l'écrivain scelle l'événement
`noortrace.journal.politique` (valeur en ligne `{ policy_version,
policy_sha256 }`, EX-10.21), **puis** applique la nouvelle politique : tout
appel dont le pas 3 de 4.4 commence après le scellement est évalué avec la
nouvelle politique et porte le nouveau `code.policy_version` ; les appels déjà
en cours finissent avec l'ancienne. Un changement de `policy.servers`
provoque la reconnexion des serveurs concernés et un `tools/list_changed`
vers les hôtes (EX-4.15) ; un changement de `policy.redaction.name` prend
effet pour toute pièce construite après le scellement. Après le scellement,
le noyau envoie `charger` avec la nouvelle version (EX-7.15) ; tant que le
service n'a pas répondu, tout outil est susceptible d'approbation (EX-7.4).
Le noyau garde l'`expire_after_ms` et la politique d'approbation de chaque
version tant qu'un ticket créé sous elle peut encore être décidé, relayé ou
expiré (SG-4, SG-7, RL-4, EX-9.4) : il les relit dans la pièce de l'ensemble
de politique de cette version (EX-8.11).

**EX-15.6** L'événement de politique porte `delegation.launched_by =
"noortrace-enregistreur"`, `scope = "journal:administration"`,
`code.policy_version` = la **nouvelle** version, `effects = [{ "system":
"noortrace", "action": "ecriture", "object": "politique:<policy_version>",
"amount": null, "currency": null }]` (section 9.1), `context = []`.

### 15.6 Commande de validation

**EX-15.7** `noortrace validate-config <fichier>` exécute les pas 1 à 3 de
15.4 sans ouvrir ni le stockage, ni le bail, ni le signataire, ni les
secrets (les références sont vérifiées en forme, pas résolues), imprime le
rapport (erreurs puis avertissements, dont ceux de la politique
d'approbation), et rend `0` si aucune erreur, `2` sinon. La partie
« schéma » est reproductible hors de l'enregistreur, les trois schémas
chargés ensemble :

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 --all-errors \
  -s spec/schemas/configuration-enregistreur-v0.schema.json \
  -r spec/schemas/politique-redaction-v0.schema.json \
  -r spec/schemas/politique-approbation-v0.schema.json \
  -d ma-configuration.json
```

La partie « règles que le schéma n'exprime pas » n'est couverte que par la
commande du démon et par les tests de CT-9.

## 16. Objectifs de performance et de capacité, méthode de mesure

Ces objectifs sont des **cibles à mesurer en phase 2**, pas des promesses : la
colonne « Résultat » du rapport de mesure (16.3) restera vide jusqu'à la
première mesure, et une cible non atteinte est un fait à publier, pas à
cacher ; chaque mesure publiée DOIT être reproductible depuis le dépôt
(16.2).

### 16.1 Objectifs

| Grandeur | Définition | Cible | Condition |
|---|---|---|---|
| **Latence ajoutée par appel relayé** | `(t_reponse_hote − t_recu) − (t_reponse − t_envoi)` : le temps total vu par l'hôte, moins le temps passé au serveur d'outils (instants de 4.4, horloge monotone) ; comprend la politique, la rédaction, les pièces, le scellement, la signature, l'ajout au segment et le `fdatasync` | **p50 ≤ 5 ms, p99 ≤ 50 ms** | `fdatasync` sur disque local (NVMe ou SSD), signataire de classe D ou C (la latence d'un signataire réseau de classe B est mesurée à part et ajoutée), arguments ≤ 4 KiB, résultat ≤ 16 KiB, politique `pii-v1`, une connexion d'hôte |
| **Latence ajoutée au premier octet d'un flux SSE** | Temps entre la réception du premier octet du fournisseur et son émission vers l'hôte, par la passerelle | **≤ 10 ms** | Fournisseur simulé émettant un événement toutes les 50 ms ; la mesure vaut pour chaque octet, pas seulement le premier (aucun tampon, EX-5.11) |
| **Débit** | Événements rendus durables par seconde, par instance | **≥ 500 événements/s** | Validation groupée (`group_max_events: 64`, `group_max_wait_ms: 5`), 16 connexions d'hôte concurrentes, mêmes tailles que ci-dessus |
| **Latence ajoutée par échange de modèle hors flux** | `(t_reponse_hote − t_recu) − (t_reponse − t_envoi)` pour `/v1/messages` sans `stream` | p50 ≤ 5 ms, p99 ≤ 50 ms | Corps de requête ≤ 32 KiB, réponse ≤ 16 KiB |
| **Signature** | Durée d'un appel `sign` du signataire | mesurée et publiée par classe de backend, aucune cible : c'est le backend du client | classes A (SoftHSM2 en test, matériel chez le client), B (Vault/OpenBao en conteneur), C, D |
| **Taille sur disque** | Octets par événement dans le segment, octets de pièces par appel | mesurée, aucune cible ; attendu de l'ordre de 2 à 3 KiB par événement (la ligne de l'annexe A fait 2465 octets) | — |
| **Reprise** | Temps de relecture du dernier segment et du journal d'intention au démarrage (EX-12.10) | ≤ 2 s pour un segment de 256 MiB | disque local |
| **Mémoire** | Résidente à vide et sous charge de débit | mesurée, aucune cible en version 0 | — |

**EX-16.1** Les cibles de latence s'entendent **hors temps du serveur amont**
et **hors réseau entre l'hôte et l'enregistreur** ; la méthode (16.2) place
l'hôte de test et le serveur d'outils nul sur la même machine que
l'enregistreur, pour que les deux soustractions soient fiables.

### 16.2 Méthode

**EX-16.2** La mesure est faite par un harnais publié dans le dépôt
(`scripts/mesures/ct-2-perf.mjs`, phase 2), reproductible par `npm run
mesures:ct2`, qui :

1. lance l'enregistreur avec une configuration de mesure publiée
   (`spec/vecteurs/ct-2/mesures/configuration-mesure.json`, classe D, bail
   `file`, stockage dans un répertoire temporaire du disque local, politique
   `pii-v1`) ;
2. lance un **serveur d'outils nul** (Streamable HTTP, ère moderne) qui répond
   à tout `tools/call` par un `result` fixe de la taille demandée en moins de
   0,1 ms, et un **fournisseur de modèle simulé** (le simulateur de l'API
   Messages de la section 19, en mode flux et hors flux) ;
3. lance un **hôte de test** (client MCP de référence, ère moderne, stdio et
   HTTP ; client HTTP pour la passerelle) qui émet `N = 20 000` appels après
   un échauffement de 2 000, avec 1 puis 16 connexions concurrentes, et
   enregistre pour chaque appel `t_recu_hote` et `t_reponse_hote` (horloge
   monotone de l'hôte) ;
4. lit dans le journal d'exploitation de l'enregistreur, pour chaque appel
   (corrélation par l'`id` JSON-RPC d'hôte), `t_recu`, `t_envoi`, `t_reponse`
   et l'instant du `fdatasync` ; la latence ajoutée est calculée comme en 16.1
   ; les percentiles sont calculés sur `N` (méthode du plus proche rang) ;
5. mesure le premier octet SSE en horodatant chaque octet reçu par l'hôte de
   test et chaque octet émis par le fournisseur simulé (même machine, même
   horloge) ;
6. mesure le débit comme `N / (t_dernier_fdatasync − t_premier_recu)` avec
   16 connexions ;
7. écrit le rapport (16.3) et le compare aux cibles ; le code de retour est
   `0` que les cibles soient atteintes ou non (la mesure n'est pas un test de
   régression ; CT-9 décide d'un seuil de régression plus tard).

**EX-16.3** Le rapport nomme la machine (processeur, mémoire, type de disque,
système, version du noyau, version de Node.js), la version de l'enregistreur
(`code.recorder`), la configuration employée (son `sha256`), les tailles de
charge, et sépare la latence du signataire ; une mesure faite avec un
`fdatasync` désactivé ou un disque en mémoire est marquée comme telle et ne
compte pas pour les cibles.

### 16.3 Format du rapport

`spec/vecteurs/ct-2/mesures/rapport-<AAAA-MM-JJ>.json` :

```json
{
  "version": 0,
  "measured_at": "2026-12-01T10:00:00.000Z",
  "recorder": "0.2.0",
  "machine": { "cpu": "…", "memory_bytes": 0, "disk": "nvme", "os": "…", "kernel": "…", "node": "22.22.0" },
  "configuration_sha256": "0x…",
  "fsync_enabled": true,
  "results": [
    { "name": "latence_appel_relaye", "unit": "ms", "n": 20000, "connections": 1, "p50": null, "p99": null, "target_p50": 5, "target_p99": 50, "met": null },
    { "name": "latence_premier_octet_sse", "unit": "ms", "n": 20000, "connections": 1, "max": null, "target_max": 10, "met": null },
    { "name": "debit", "unit": "events/s", "n": 20000, "connections": 16, "value": null, "target_min": 500, "met": null },
    { "name": "signature", "unit": "ms", "backend": "file", "p50": null, "p99": null },
    { "name": "octets_par_evenement", "unit": "bytes", "mean": null },
    { "name": "reprise", "unit": "ms", "segment_bytes": 268435456, "value": null, "target_max": 2000, "met": null }
  ]
}
```

Les clés sont en anglais, les valeurs énumérées en français sans accent ; le
rapport n'est pas une pièce et n'entre pas dans la chaîne.

## 17. Supervision

### 17.1 Santé

**EX-17.1** Le démon sert sur `supervision.health_listen` (local par défaut) :

| Chemin | Réponse | Usage |
|---|---|---|
| `GET /healthz` | `200` et `{"status":"ok"}` ; `200` et `{"status":"degraded","reasons":[…],"since":"<horodatage>"}` où chaque raison est `stockage`, `cle`, `bail`, `horloge`, `attente`, `approbation` ou `serveur:<alias>` ; `503` et `{"status":"down","reasons":[…]}` quand aucun appel ne peut être servi (bail non détenu, clé indisponible) ; `200` et `{"status":"standby"}` pour une instance passive | Sonde de vivacité et d'état ; les raisons sont celles de la matrice de 14.2 ; le nom d'un serveur d'outils n'apparaît qu'à un appelant local ou authentifié (un `degraded` public ne nomme pas les serveurs, précaution reprise de TBXark/mcp-proxy, R9 F-63) |
| `GET /readyz` | `200` quand les frontaux écoutent et que le bail est détenu, `503` sinon | Sonde de disponibilité pour un orchestrateur |
| `GET /metrics` | Exposition au format texte Prometheus si `supervision.metrics` est vrai | 17.2 |

### 17.2 Métriques

Noms fixes, préfixe `noortrace_` ; étiquettes en anglais, valeurs en français
sans accent quand elles sont énumérées. Aucune étiquette ne porte un argument,
un nom d'utilisateur, un identifiant de ticket ou un nom d'hôte de client.

| Nom | Type | Étiquettes | Sens |
|---|---|---|---|
| `noortrace_events_total` | compteur | `kind` (`appel_outil`, `echange_modele`, `decision`, `rotation`, `politique`, `reprise`, `attente`), `status` (`executee`, `retenue`, `refusee`), `is_error` | Événements rendus durables |
| `noortrace_relay_latency_ms` | histogramme (bornes 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000) | `path` (`mcp`, `modele`, `sdk`), `class` | Latence ajoutée par appel, définition 16.1 |
| `noortrace_upstream_latency_ms` | histogramme | `server` (alias) ou `provider` (libellé) | `t_reponse − t_envoi` |
| `noortrace_fsync_duration_ms` | histogramme | — | Durée de chaque `fdatasync` |
| `noortrace_fsync_group_size` | histogramme | — | Événements par `fdatasync` (12.3) |
| `noortrace_sign_duration_ms` | histogramme | `backend` | Durée de `sign` |
| `noortrace_sse_first_byte_ms` | histogramme | `provider` | Latence ajoutée au premier octet d'un flux |
| `noortrace_model_tokens_total` | compteur | `provider` (libellé), `direction` (`entree`, `sortie`) | Jetons déclarés par le fournisseur dans `usage` (EX-5.20) : Anthropic `input_tokens` et `output_tokens` (R2 F-A20) ; Chat Completions `prompt_tokens` et `completion_tokens` (R2 F-O9) ; Responses `input_tokens` et `output_tokens` (R2 F-R2) ; les détails de cache et de raisonnement ne sont pas comptés en version 0 |
| `noortrace_calls_blocked_total` | compteur | `code` (`-31010`, …), `reason` (`data.reason` de `-31010`, dont `redaction` ; `direction` de `-31013`, dont `quota`), `class` | Appels bloqués (14, EX-4.47, EX-10.23) |
| `noortrace_approval_signals_total` | compteur | `state` (`en_attente`, `refuse`, `expire`) | Signaux d'approbation rendus (EX-4.49) |
| `noortrace_approval_remises_refused_total` | compteur | `check` (`SG-1` à `SG-7`) | Remises refusées (EX-7.5) |
| `noortrace_approval_relays_refused_total` | compteur | `check` (`RL-1` à `RL-4`, `retenue_decidee`) | Relais refusés (EX-7.21) et `retenue` refusées (EX-7.17) |
| `noortrace_redaction_budget_exceeded_total` | compteur | `operation` (`piece`, `extract`, `valeur`, `jetons`), `scope` | Dépassements du budget de rédaction (EX-10.23, opérations 1 à 4) |
| `noortrace_pending_events` | jauge | — | Taille de la file d'attente (14.5) |
| `noortrace_pending_oldest_ms` | jauge | — | Âge de l'événement en attente le plus ancien |
| `noortrace_degraded` | jauge | `reason` | 1 en mode dégradé pour cette raison, 0 sinon |
| `noortrace_lease_epoch` | jauge | — | Époque du bail détenu ; 0 si non détenu |
| `noortrace_lease_renew_failures_total` | compteur | `store` | Renouvellements en échec |
| `noortrace_redactions_total` | compteur | `type` (`iban`, `avs`, `carte`, `email`, `telephone`, `regex`, `champ`), `scope` | Correspondances rédigées (EX-10.17) |
| `noortrace_pieces_bytes_total` | compteur | `scope` | Octets de pièces écrits |
| `noortrace_segment_bytes` | jauge | — | Taille du segment courant |
| `noortrace_tools_announced` | jauge | `server` | Outils annoncés par serveur |
| `noortrace_tools_rejected_total` | compteur | `server`, `reason` | Rejets d'EX-4.11 |
| `noortrace_tool_definition_changes_total` | compteur | `server` | Changements d'empreinte (EX-4.16) |
| `noortrace_upstream_errors_total` | compteur | `server` ou `provider`, `kind` (`injoignable`, `delai`, `jsonrpc`, `http_4xx`, `http_5xx`, `flux_incomplet`) | Erreurs amont |
| `noortrace_anchor_pending` | jauge | `anchor` (`registre`, `rfc3161`, `ots`) | Périodes dont l'ancre n'est pas confirmée |
| `noortrace_worm_copy_pending` | jauge | — | Segments fermés sans copie WORM vérifiée |
| `noortrace_clock_skew_ms` | jauge | — | Dernier écart mesuré (EX-7.10) |
| `noortrace_build_info` | jauge (1) | `version`, `protocol_versions` | Version du logiciel |

### 17.3 Journal d'exploitation

Le format est celui de la section 9.2 (NDJSON, hors chaîne) ; cette section
fixe ce que la supervision y attend et ce qui n'y va jamais.

**EX-17.2** Chaque ligne a la forme d'EX-9.5 : `ts` (CT-1 §3), `level`
(`debug`, `info`, `warning`, `error`), `component`, `event` (code ASCII en
`snake_case`), `org_id`, `journal_id`, `seq`, `host` (identité de connexion
d'hôte), `request_id`, `data` (objet propre à l'événement ; il porte
`instance_id` dans un déploiement à plusieurs instances, et `server`
(alias) quand un serveur d'outils est concerné). Les noms d'événements
employés par cette spécification, en plus de ceux de 9.2 (`tool_call_relayed`,
`tool_rejected`, `tool_definition_changed`, `relay_out_of_chain`,
`correlation`, `child_stderr`, `degraded_enter`, `degraded_exit`,
`lease_acquired`, `lease_lost`, `segment_rotated`, `period_closed`,
`intent_recovered`, `clock_skew`) : `startup`, `config_reloaded`,
`config_reload_rejected`, `redaction_applied`, `call_blocked`,
`call_passthrough_pending`, `pending_flushed`, `segment_truncated`,
`segment_corrupted`, `storage_unavailable`, `signer_unavailable`,
`lease_standby`, `intention_levee_implicite`, `intention_sans_contexte`,
`upstream_unreachable`, `upstream_timeout`, `provider_error`,
`approval_pending`, `approval_service_unavailable`,
`approval_response_invalid`, `approval_candidates`, `approval_deferred`,
`approval_expired_deferred`, `approval_remise_refused`,
`approval_relay_refused`, `identifiant_en_collision`,
`redaction_budget_exceeded`, `effect_omitted`, `anchor_pending`,
`registry_pending`, `clock_backstep`, `disk_low`, `pending_limit_reached`,
`worm_copy_failed`, `pieces_purged`, `integrity_check`, `auth_failed`,
`model_exchange_relayed` (pendant de `tool_call_relayed` pour un échange de
modèle : `data` porte le libellé de la route, `code.model`, le statut HTTP,
`request-id`, les `sha256` des pièces, le `seq` et l'objet `usage` tel que
reçu, EX-5.20).

**EX-17.3** Ne vont **jamais** dans le journal d'exploitation : une pièce ou
un fragment de pièce (arguments, résultats, messages, prompt), une valeur
rédigée ou sa position, un en-tête d'authentification ou un secret, un jeton
d'hôte, une valeur de `_meta` autre que les clés `io.modelcontextprotocol/*`
et `noortrace/*`, le message soumis au signataire. Les tailles et les
`sha256` sont admis. Le journal d'exploitation est une donnée du client,
conservée avec le journal (12.7, Olico art. 9 al. 1 let. b ch. 4) et
protégée comme lui (18).

**EX-17.4** Le fichier est tourné par taille
(`supervision.ops_log.rotate_max_bytes`, `keep_files` : les clés
`logging.rotate_bytes`, `logging.keep_files` et `logging.child_stderr_max_bytes`
de 9.2 sont celles du membre `supervision.ops_log`, 15.1) ; une ligne qui ne
peut pas être écrite (disque plein) est comptée dans
`noortrace_ops_log_dropped_total` et n'arrête pas le relais (EX-9.7) : le
journal d'exploitation n'est pas la chaîne.

### 17.4 Alertes

Alertes **prescrites** (le client les branche sur son système ; CT-8 donne
les règles Prometheus) :

| Alerte | Condition | Gravité |
|---|---|---|
| Mode dégradé | `noortrace_degraded == 1` pendant plus de 60 s | critique pour `cle`, `bail`, `horloge` ; majeure pour `stockage`, `attente` ; mineure pour `serveur:*` |
| Appels bloqués | `rate(noortrace_calls_blocked_total[5m]) > 0` | majeure |
| Événements en attente | `noortrace_pending_events > 0` pendant plus de 300 s, ou `noortrace_pending_oldest_ms > pending_max_ms / 2` | majeure |
| Bail | `noortrace_lease_epoch == 0` sur l'instance attendue active, ou `increase(noortrace_lease_renew_failures_total[5m]) > 0` | critique |
| Ancre en retard | `noortrace_anchor_pending > 0` pendant plus de 2 h | majeure (la preuve de date de ces périodes attend) |
| Copie WORM en retard | `noortrace_worm_copy_pending > 0` pendant plus de 1 h | majeure |
| Horloge | `abs(noortrace_clock_skew_ms) > warn_skew_ms` | mineure ; critique si `degraded{reason="horloge"}` |
| Définition d'outil changée | `increase(noortrace_tool_definition_changes_total[1h]) > 0` | mineure, à examiner : c'est le signal du « rug pull » (EX-4.16) |
| Fourche | `journal_fork` dans le journal d'exploitation : un fichier d'époque inférieure a grandi après la reprise (EX-13.10) | critique |
| Panne après relais | `increase(noortrace_calls_executed_not_durable_total[5m]) > 0` (`-31017`, EX-4.46) | critique : un effet a eu lieu sans événement durable |
| Relais refusé ou identifiant en collision | `increase(noortrace_approval_relays_refused_total[5m]) > 0` (EX-7.17, EX-7.21) | critique : le service d'approbation a demandé un relais ou une `retenue` que la chaîne ne justifie pas |
| Remise refusée | `increase(noortrace_approval_remises_refused_total[1h]) > 0` (EX-7.5), ou `politique_invalide` au `charger` (EX-7.15) | majeure : défaut ou compromission du service d'approbation |
| Budget de rédaction | `increase(noortrace_redaction_budget_exceeded_total[1h]) > 0` (EX-10.23) | mineure quand une pièce de lecture ou une valeur a perdu son contenu ; majeure quand un appel a été bloqué (`noortrace_calls_blocked_total{reason="redaction"}`, opération 1) : examiner la taille ou la forme des entrées, et les motifs nommés |
| Clé du MAC de relais | `relay_mac_key_mismatch` dans le journal d'exploitation (EX-7.22, 13.4) | critique : deux instances d'un même journal n'ont pas la même clé ; la bascule est refusée |
| Quota d'un hôte | `increase(noortrace_calls_blocked_total{code="-31013",reason="quota"}[5m]) > 0` (EX-4.47) | mineure : un hôte atteint son quota d'octets, de requêtes ou de temps de capture |
| Latence | `histogram_quantile(0.99, noortrace_relay_latency_ms) > 50` sur 15 min | mineure |
| Disque | `disk_low` dans le journal, ou espace libre < 2 × `min_free_bytes` | majeure |

### 17.5 Contrôles périodiques

**EX-17.5** Un fil de supervision exécute, à une cadence fixe en version 0
(toutes les heures après la clôture de période, et une fois par jour pour la
relecture complète) : la relecture et la vérification des
segments fermés de la journée (EX-12.10, pas 2, sur tout le segment) ; la
comparaison `sha256` de chaque segment fermé avec sa copie WORM (EX-12.17) ;
la vérification que chaque période close a son manifeste, sa signature, et
que la continuité de CT-1 §10.3 tient ; le `health()` du signataire. Les
résultats vont dans le journal d'exploitation (`integrity_check`), avec
`noortrace_integrity_check_failures_total`. C'est le contrôle que demande
l'Olico, art. 10 al. 1 : « L'intégrité et la lisibilité des supports
d'information sont régulièrement contrôlées » (R5 § 1.9).

## 18. Sécurité de l'enregistreur lui-même

L'enregistreur est la pièce que tout le reste suppose honnête ; cette section
fixe ce qui borne sa compromission. L'analyse de menace complète, la revue de
code et la conformité sont de CT-7.

### 18.1 Surface

**EX-18.1** Surface d'écoute, exhaustive : la prise locale des connecteurs
stdio et du SDK (`mcp.socket`, `sdk.socket` ; propriétaire = utilisateur du
démon, mode `0660`, groupe des utilisateurs d'hôtes autorisés) ; le point de
terminaison Streamable HTTP (`mcp.http.listen`, `127.0.0.1` par défaut) ; la
passerelle de modèle (`model.listen`) ; le serveur ICAP (`model.icap.listen`)
en mode `icap` ; la santé et les métriques (`supervision.health_listen`) ;
rien d'autre. Aucune interface d'administration réseau en version 0 : la
gestion passe par la ligne de commande locale (`noortrace-ctl`, même
utilisateur que le démon) et par la configuration.

**EX-18.2** Surface sortante, exhaustive : les serveurs d'outils configurés,
les fournisseurs de modèle des routes, le signataire (classes A et B), le
magasin de bail, le support WORM, le registre et les ancres (CT-4, CT-5), le
service d'approbation (CT-3), le coffre de secrets (références `vault`). Le
démon n'a aucune autre destination : pas de télémétrie, pas de mise à jour
automatique, pas de résolution d'URL fournie par l'hôte (EX-4.30 : une URL
d'elicitation est relayée, jamais visitée). La seule exception est la
découverte OAuth d'un serveur d'outils (EX-4.40), dont les URL viennent du
serveur : en production, elles sont épinglées dans la configuration et le
démon n'en suit pas d'autres ; en développement, elles sont bornées
(HTTPS, même origine, aucune redirection, plages privées et réservées
refusées). Le pare-feu du client PEUT le vérifier par une liste de
destinations (4.9).

### 18.2 Authentification et autorisation

**EX-18.3** Tout appelant est authentifié : identité du processus pair sur
les prises locales, jeton OAuth 2.1 ou jeton statique en HTTP (EX-4.39),
identifiants propres de l'enregistreur vers chaque amont (EX-4.40), aucun
relais de jeton (EX-4.41). Les jetons statiques sont comparés en temps
constant ; une tentative échouée est consignée (`auth_failed`, sans le jeton)
et limitée en fréquence **par identifiant de jeton présenté** (les huit
premiers caractères hexadécimaux du SHA-256 du jeton) et par connexion (10
échecs par minute, puis refus de ce jeton ou de cette connexion pendant
60 s), **jamais par adresse source** : sur `127.0.0.1` ou derrière un
mandataire inverse, tous les hôtes partagent une adresse, et un processus
local ne doit pas pouvoir bloquer les hôtes légitimes ; un jeton valide
n'est jamais refusé à cause des échecs d'un autre. Les points `/healthz` et
`/readyz` sont publics sur leur
adresse d'écoute ; `/metrics` l'est aussi mais ne porte aucune donnée de
client (17.2).

### 18.3 Moindre privilège

**EX-18.4** Le démon tourne sous un utilisateur système dédié, sans
interpréteur de commandes, sans `CAP_LINUX_IMMUTABLE` (EX-12.18), sans accès
en écriture ailleurs que dans `storage.root`, le journal d'exploitation, le
répertoire des prises et les répertoires temporaires des serveurs stdio ; le
système de fichiers racine est en lecture seule quand le conteneur le permet
(CT-8). Les serveurs d'outils stdio sont lancés par le démon sous un
utilisateur **distinct** du sien (`transport.user`), sans droit sur
`storage.root`, les secrets, la configuration ni les prises, dans le bac à
sable de `policy.servers.<alias>.transport.sandbox` (EX-3.4, EX-3.5) ; leur
environnement ne contient que les variables déclarées (15.2), jamais celles
du démon. Les secrets DEVRAIENT être désignés par des références `{ "file":
… }` plutôt que `{ "env": … }` : l'environnement d'un processus est lisible
dans `/proc/<pid>/environ` par qui passe le contrôle ptrace (EX-3.5).

**EX-18.5** Le processus de l'hôte et celui de l'agent n'ont aucun droit sur
`storage.root` (EX-3.2) ; la prise locale est le seul lien. Le fichier de
configuration est lisible par le seul utilisateur du démon (il contient des
chemins et des références, pas des secrets, mais il décrit la politique). Les
fichiers de secrets sont `0400`/`0600` (15.2).

### 18.4 Intégrité de la configuration et du logiciel

**EX-18.6** Au démarrage et à chaque rechargement, le démon consigne le
`sha256` des octets du document de configuration (`startup`,
`config_reloaded`) et le `policy_sha256` (EX-10.21) ; l'exploitant peut ainsi
rapprocher la configuration en vigueur de celle qu'il a approuvée. La
signature du document de configuration par l'exploitant (vérification d'une
signature détachée avant chargement) n'est pas dans la version 0 (section 21).
L'image conteneur publiée porte une empreinte et une attestation de
provenance de la chaîne de construction (CT-8) ; `code.recorder` dans chaque
événement est la version du logiciel, de sorte qu'une version compromise est
nommée dans la chaîne.

**EX-18.7** Les secrets résolus sont tenus en mémoire du démon dans des
tampons effacés à l'arrêt ; le démon demande au système de ne pas écrire sa
mémoire sur disque (`mlockall` ou équivalent) quand le déploiement le permet
(avertissement consigné sinon) et désactive les fichiers de vidage mémoire
(`core dumps`) : sous Linux par `prctl(PR_SET_DUMPABLE, 0)` (EX-3.5), qui
rend aussi le processus non traçable par un processus de même utilisateur.
La graine de classe C n'est jamais écrite en clair.

**EX-18.8** **Service d'approbation.** Ses décisions ne sont pas signées
quand elles disent `autorise` ou `refuse` (seules les décisions `approuve`
portent les signatures des approbateurs, vérifiées par EX-7.5) : le canal
qui les porte DOIT donc être authentifié. Le démon authentifie le service :
sur une prise Unix, par l'identifiant d'utilisateur attendu du pair
(`policy.approval.service.peer_user`) et un répertoire de prise non
inscriptible par les hôtes ni par les agents ; en HTTP, par mTLS ou par un
jeton (référence de secret). Un `token` nul n'est admis que sur une prise
Unix dont le pair est vérifié. Le service d'approbation de démonstration
embarqué dans l'enregistreur (19.2) est refusé en `environment:
"production"`.

### 18.5 Ce qu'un enregistreur compromis peut et ne peut pas faire

Dit en clair, pour le modèle de menace de l'architecture (« L'enregistreur
lui-même est compromis ») :

- il **peut** omettre des événements, en forger de nouveaux et les signer tant
  qu'il a l'usage de la clé, et rédiger plus ou moins que la politique ;
- il **ne peut pas** réécrire une période dont la racine a été ancrée (CT-5)
  ou enregistrée (CT-4) sans que la réécriture se voie ; la fenêtre est d'une
  heure (CT-1 §7.2) ; la contresignature interne optionnelle de
  l'architecture la réduit ;
- il **ne peut pas** exporter une clé de classe A ou B non exportable ; la
  rotation d'urgence (EX-11.16) et la révocation (CT-4) ferment la fenêtre ;
- il **ne peut pas** effacer les copies WORM en mode Compliance ou Locked
  (12.6) ni les événements que les hôtes ont déjà vus confirmés par une
  réponse (ils existent chez le client sous forme d'effets) ;
- ce qu'il a vu passer en clair (arguments, prompts) a transité par sa
  mémoire : la rédaction protège le journal, pas le processus. La séparation
  en démon dédié, hors de l'hôte (3.4), vise à ce qu'une compromission de
  l'agent ne soit pas une compromission de l'enregistreur ; l'inverse relève
  de CT-7 et de l'exploitation.

## 19. Démonstration de référence et intégrations

La démonstration DOIT tenir en une commande : conçue ici, construite en
phase 2. Les fichiers d'intégration couvrent les hôtes de la section 19.5 ;
chacun est marqué
**« à tester en phase 2 »** : les formats viennent des pages officielles lues
le 2026-10-22 (digest R7), aucun n'a encore été exécuté contre un
enregistreur.

### 19.1 Topologie `docker compose`

`docker compose up` (fichier `demo/compose.yaml` du dépôt public, phase 2)
lance six services sur quatre réseaux ; l'agent ne peut joindre que
l'enregistreur, ce qui est la règle de 4.9 appliquée au réseau Compose :

| Service | Image | Réseaux | Rôle |
|---|---|---|---|
| `enregistreur` | `noortrace/enregistreur:<version>` | `hotes`, `outils`, `fournisseurs`, `registre` | Le démon : frontal MCP en Streamable HTTP (`:8300/mcp`), passerelle de modèle (`:8400`), santé (`:8500`) ; classe de garde D (clé de test `rec-test-01` de CT-1 §13, graine publique), bail `file`, stockage sur un volume `journal`, politique `pii-v1`, configuration `demo/configuration-demo.json` (valide contre le schéma de la section 15 et par EX-15.4 : sa politique d'approbation est un document `politique-approbation-v0`, en mode `erreur`) |
| `outils-demo` | `noortrace/outils-demo:<version>` | `outils` | Serveur d'outils MCP de démonstration (ère `2026-07-28`, Streamable HTTP) : trois outils, `claims.get` (lecture), `claims.search` (lecture), `payments.create` (écriture, gabarit d'effets), données fictives en mémoire |
| `modele-demo` | `noortrace/modele-demo:<version>` | `fournisseurs` | **Simulateur de l'API Messages** (19.3) : répond à `POST /v1/messages`, hors flux et en flux SSE, sans clé, d'après un scénario fixe |
| `agent-demo` | `noortrace/agent-demo:<version>` | `hotes` | Agent scénarisé : client MCP (ère moderne) vers `http://enregistreur:8300/mcp`, SDK de modèle avec `ANTHROPIC_BASE_URL=http://enregistreur:8400` et une clé factice ; joue le scénario de 19.2 puis se termine |
| `registre-dev` | `noortrace/registre-dev:<version>` | `registre` | Instance de développement du registre (`chain/` du dépôt : nœud de développement, contrats `RecorderRegistry`, `PeriodRegistry`, `AttestationRegistry` déployés au démarrage, comptes Hardhat 1 à 3 comme approbateurs) ; l'enregistreur y inscrit sa clé et y enregistre la période close |
| `verificateur` | `noortrace/verificateur:<version>` | `registre` (lecture du certificat de commit) + volume `journal` en lecture seule | Attend la fin de `agent-demo`, demande à l'enregistreur la clôture anticipée de la période de démonstration (commande d'exploitation `noortrace-ctl close-period --now`, admise seulement en `environment: "developpement"`), exporte le dossier de l'événement `payments.create` (CT-1 §11), le vérifie hors ligne (`scripts/verify/dossier.mjs`), imprime le résultat et termine avec le code du vérificateur |

Réseaux : `hotes` (agent ↔ enregistreur), `outils` (enregistreur ↔ serveur
d'outils), `fournisseurs` (enregistreur ↔ modèle), `registre` (enregistreur
et vérificateur ↔ registre). `agent-demo` n'est attaché qu'à `hotes` : il ne
peut atteindre ni `outils-demo` ni `modele-demo`, ce que la démonstration
affiche (« l'agent ne joint que l'enregistreur »). Aucun port n'est publié sur
la machine hôte sauf `8500` (santé) et, en option, `8300`/`8400` pour brancher
un vrai hôte.

**EX-19.1** La démonstration DOIT se dérouler en **moins de deux minutes** sur
un portable, sans clé d'API et sans accès à Internet
autre que le téléchargement des images ; le temps est mesuré par
`verificateur` et imprimé. Elle ne contient aucune adresse de production,
aucune clé réelle et aucun prix.

### 19.2 Séquence

1. `enregistreur` démarre : validation de la configuration (15.4), bail,
   clé de test, événement de politique (`seq 1`, `noortrace.journal.politique`,
   `policy_version: "demo-2026-12"`, ensemble dont `approval.rules` est un
   document `politique-approbation-v0` en mode `erreur` ; le vecteur
   `journal-demo` garde l'ensemble antérieur à CT-3, `demo-2026-11`, B.6),
   inscription de la clé publique au
   `registre-dev` (CT-4), connexion à `outils-demo`, `server/discover`,
   `tools/list` (trois outils annoncés `demo__claims.get`,
   `demo__claims.search`, `demo__payments.create`), santé `ok`.
2. `agent-demo` démarre quand `enregistreur` est `ready` : échange de modèle
   n° 1 (`POST /v1/messages`, hors flux, en-têtes `X-Noortrace-Token` et
   `X-Noortrace-Run-Id: run-demo-0001`, connexion d'hôte `agent-demo` de
   `model.hosts`, groupe `demo`) — le simulateur répond un appel d'outil ; le
   modèle voit les outils sous les noms que l'hôte lui donne (ici le nom
   annoncé, `.` remplacé par `_` : `demo__claims_get`, EX-4.12 ; la connexion
   d'hôte porte `tool_name_sanitize: true`) ; événement `seq 2`
   (`noortrace.modele.echange`, `code.model = "demo/modele-demo-1"` : libellé
   `demo` de la route de démonstration,
   prompt système rédigé en pièce, délégation de la connexion d'hôte).
3. `tools/call demo__claims.get` (connexion MCP `agent-demo` de `mcp.hosts`,
   même groupe `demo`, `run_id` déclaré dans `_meta`) : lecture, autorisée,
   relayée ; événement `seq 3` (`intent` corrélé à `seq 2`, EX-5.22).
4. Échange de modèle n° 2, **en flux SSE** : le simulateur émet un texte puis
   un bloc `tool_use` `demo__payments.create` avec un IBAN fictif dans
   `input` ; l'enregistreur relaie le flux sans tampon et réassemble la forme
   consolidée ; événement `seq 4` (réponse rédigée : `[REDIGE:iban]`,
   `redacted: true`).
5. `tools/call demo__payments.create` : classe `ecriture`, règle
   d'approbation `montant > 5000` → `a_approuver`, `ticket_state:
   "nouveau"` ; événement `seq 5` (`retenue`) ; le mode `erreur` rend le
   signal d'approbation, résultat `isError: true` qui porte le ticket et
   `state: "en_attente"` (EX-4.49) ; l'agent affiche « en attente
   d'approbation ».
6. Un service `approbateur-demo` (distinct de l'agent et de l'enregistreur,
   seul détenteur des clés de démonstration des comptes Hardhat 1 à 3,
   réseau `registre` et prise du service d'approbation de démonstration)
   joue les approbateurs : il signe la décision avec les comptes Hardhat 1
   et 2 (CT-1 §6.3) et la remet au service d'approbation de démonstration
   embarqué dans `enregistreur` (admis seulement en développement, EX-18.8 ;
   CT-3 fournit le vrai) ; événement `seq 6`
   (`noortrace.approbation.decision`, `approval.at` = son `ts`, EX-7.11).
7. L'agent ré-émet l'appel : CT-3 reconnaît le ticket décidé et rend
   `autorise` avec `ticket_state: "approuve"` et l'objet `approval` ; le
   noyau fait RL-1 à RL-4 (EX-7.21) ; l'appel relayé reprend de `seq 5`
   `policy` (`decision: "a_approuver"`, `rule`, `ticket`), `intent` et `code`
   (EX-7.12) ; intention écrite et `fdatasync` ; relais ; réponse ; événement
   `seq 7` (`executee`, effets `{ "system": "demo", "action": "ecriture",
   "object": "PAY-…", "amount": "7400.00", "currency": "CHF" }`) ;
   `consommer` (EX-7.20).
8. Échange de modèle n° 3 (fin de tour) : événement `seq 8` ; `agent-demo`
   se termine.
9. `verificateur` : clôture anticipée de la période ; manifeste signé ;
   `submitPeriod` sur `registre-dev`, signé au seuil par `approbateur-demo`
   (comptes Hardhat 1 et 2, les mêmes qui ont inscrit la clé au pas 1), la
   transaction étant relayée par la clé de chaîne de l'enregistreur ;
   `anchor` ; certificat de commit lu ;
   export du dossier de `seq 7` (douze parties, dont `registre.json`,
   `certificat-commit.json`, `validateurs.json` ; `jeton-rfc3161.der` et
   `preuve.ots` absents avec la raison « démonstration hors ligne ») ;
   vérification ; impression.

### 19.3 Simulateur de l'API Messages

**EX-19.2** `modele-demo` reproduit la forme documentée de l'API Messages
(R2) et rien de plus : `POST /v1/messages` ; en-têtes `x-api-key` ou
`Authorization: Bearer` acceptés sans vérification, `anthropic-version`
requis et recopié tel quel ; corps `model`, `max_tokens`, `messages`,
`system`, `tools`, `stream` ; réponse hors flux = objet `Message` (`id`,
`type: "message"`, `role: "assistant"`, `model`, `content`, `stop_reason`,
`stop_sequence`, `usage`, R2 F-A18) ; réponse en flux = `text/event-stream`
avec la séquence `message_start`, `content_block_start`,
`content_block_delta` (`text_delta`, `input_json_delta` avec un premier
`partial_json` vide), `content_block_stop`, `message_delta` (portant
`stop_reason` et `usage` cumulatif), `message_stop`, et un `ping` inséré
(R2 F-A21, F-A22, F-A27) ; erreurs au format `{"type":"error","error":{"type",
"message"},"request_id"}` (R2 F-A32) pour un corps sans `messages` (`400
invalid_request_error`). Le scénario est choisi par le contenu du dernier
message utilisateur (trois réponses fixes) ; les identifiants `msg_…` et
`toolu_…` sont fixes pour que les vecteurs `pieces-modele` de l'annexe B
soient reproductibles. Le simulateur n'est pas un modèle et ne prétend pas
l'être : il existe pour que la démonstration n'exige aucune clé.

**EX-19.3** Option **modèle réel** : `MODELE_REEL=1 ANTHROPIC_API_KEY=… docker
compose up` reconfigure la route `/v1/messages` de l'enregistreur vers
`https://api.anthropic.com` avec `credentials: "propre"` et le secret
`{ "env": "ANTHROPIC_API_KEY" }` ; le scénario de l'agent devient un vrai
tour d'agent (le modèle décide des appels) ; les étapes 2 à 8 s'exécutent
avec les mêmes outils ; la sortie n'est plus déterministe et la durée dépend
du fournisseur. La clé n'est jamais écrite sur disque ni dans le journal.

### 19.4 Sortie attendue

Sortie de `verificateur` (extrait ; quand le modèle simulé est employé, les
valeurs imprimées ici, nombre d'événements, `seq`, approbateurs et seuil,
sont celles du vecteur `evenements/journal-demo` de l'annexe B ; les
empreintes, le segment et le dossier de `seq 7` en diffèrent, puisque la
configuration de démonstration porte une politique d'approbation conforme à
CT-3, qui change `policy_sha256`, quand `journal-demo` garde l'ensemble de
politique de la version 0.2, antérieur à CT-3, B.6 ; la `source` de
`approbations.json` suit alors CT-3 EX-8.8) :

```text
noortrace — démonstration de référence
  enregistreur    : 0.1.0, clé rec-test-01 (classe D, démonstration), bail file, époque 1
  journal         : assureur-demo / journal-demo, 8 événements, période 2026-11-10T10:00:00Z → 11:00:00Z
  registre-dev    : clé inscrite (RecorderRegistry), période enregistrée (PeriodRegistry), racine ancrée (AttestationRegistry), bloc certifié par 4 validateurs
  dossier         : dossiers/seq-7/ (demo__payments.create, approuvé par 0x7099…79c8 et 0x3c44…93bc, seuil 2 sur 3)
  vérificateur    : 27 contrôles [ok], 2 non exécutés avec raison admise (T-*, O-* : démonstration hors ligne)
  Résultat : VALIDE — cet événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste
             signé par cette clé, approuvé par ces adresses, et son ancre est dans un bloc que les validateurs nommés ont signé.
             Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne).
  Ce que l'agent n'a pas pu faire : joindre outils-demo ou modele-demo directement (réseaux séparés) ; obtenir
  le résultat de payments.create avant qu'un événement durable existe ; effacer seq 5 (sa demande retenue).
  Durée totale : 41 s
```

Le texte exact, les codes de retour (`0` si valide, `1` sinon) et les
captures (image ou enregistrement de terminal du README) sont fixés en phase
2 ; la phrase « ce que le projet ne prouve pas » DOIT y figurer toujours.

**EX-19.4** La clôture anticipée (`noortrace-ctl close-period --now`, admise
seulement en développement) **termine** le journal de démonstration : la
période close contient l'instant de la clôture, et un événement ultérieur y
tomberait (CT-1 P-3). Après elle, l'enregistreur refuse tout nouvel appel et
tout nouvel échange sur ce journal (`-31010`, `reason: "journal_clos"`) ;
brancher un vrai hôte sur les ports `8300` et `8400` exige un nouveau journal
(`docker compose down -v`, puis `up`).

### 19.5 Fichiers d'intégration, par hôte

Conventions communes : l'enregistreur tourne en démon ; le connecteur stdio
`noortrace-connecteur` (EX-3.3) est lancé par l'hôte et joint la prise
`mcp.socket` ; en Streamable HTTP, l'hôte joint `http://127.0.0.1:8300/mcp`
avec un jeton statique (EX-4.39). La passerelle de modèle écoute sur
`http://127.0.0.1:8400`. Chaque fichier est **à tester en phase 2**. Là où
l'hôte admet des consignes pour l'agent (fichier d'instructions du projet,
consigne système), le fichier d'intégration DEVRAIT reprendre la conduite de
CT-3 EX-11.9 : après le signal d'approbation `en_attente`, le dire à
l'utilisateur et ne pas répéter l'appel plus d'une fois par minute ; après
`refuse`, `expire` ou le refus par la politique (`noortrace: appel refuse
par la politique`), ne pas répéter l'appel, ne pas le fractionner ni le
reformuler (autre écriture d'un montant, d'une devise, d'un identifiant),
et le dire à l'utilisateur.

#### 19.5.1 Claude Desktop (macOS, Windows, Linux)

Fichier `claude_desktop_config.json` (macOS `~/Library/Application
Support/Claude/`, Windows `%APPDATA%\Claude\` ; ouvert par Settings →
Developer → Edit Config ; redémarrage complet requis ; chemins absolus ;
R7 F-01 à F-04). Le chemin Linux n'est documenté que par VS Code
(`$XDG_CONFIG_HOME/Claude/` ou `~/.config/Claude/`, R7 NV-06).

```json
{
  "mcpServers": {
    "noortrace": {
      "command": "/usr/local/bin/noortrace-connecteur",
      "args": ["--socket", "/run/noortrace/mcp.sock"]
    }
  }
}
```

Ce que cette intégration capture : les appels d'outils (frontal MCP). Ce
qu'elle ne capture pas : les échanges de modèle — l'application standard
n'offre pas de réglage d'URL de base documenté (R7 NV-05) ; seul le mode de
déploiement « Claude Desktop on 3P » route l'inférence vers une passerelle
(`inferenceProvider: "gateway"`, `inferenceGatewayBaseUrl`,
`inferenceGatewayAuthScheme` `bearer` ou `x-api-key` ; la passerelle doit
servir `POST /v1/messages` avec flux et outils, R7 F-91), ce que la
passerelle de la section 5 fait. Les serveurs MCP distants de Claude Desktop
passent par des « connecteurs personnalisés » dont la connexion part de
l'infrastructure d'Anthropic, pas du poste (R7 F-08) : l'enregistreur local
reste donc un serveur stdio (ou un paquet `.mcpb`, R7 F-12, prévu en phase
2). Les noms d'outils contenant un point sont refusés par l'API Messages
(EX-4.12).

#### 19.5.2 Claude Code

Fichier `.mcp.json` à la racine du projet (portée `project`), ou `claude mcp
add --transport http noortrace http://127.0.0.1:8300/mcp --header
"Authorization: Bearer ${NOORTRACE_TOKEN}"` (R7 F-16, F-18, F-24) :

```json
{
  "mcpServers": {
    "noortrace": {
      "type": "http",
      "url": "http://127.0.0.1:8300/mcp",
      "headers": { "Authorization": "Bearer ${NOORTRACE_TOKEN}" }
    }
  }
}
```

Passerelle de modèle, dans `~/.claude/settings.json` ou l'environnement (R7
F-30 à F-32) :

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8400",
    "ANTHROPIC_AUTH_TOKEN": "${NOORTRACE_TOKEN_PASSERELLE}",
    "ANTHROPIC_CUSTOM_HEADERS": "X-Noortrace-Run-Id: ${NOORTRACE_RUN_ID}",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
```

La route `/v1/messages` est en `credentials: "propre"` : le jeton envoyé par
`ANTHROPIC_AUTH_TOKEN` (`Authorization: Bearer …`, R7 F-31) est le jeton
statique de la connexion d'hôte de la passerelle (EX-5.8), une entrée de
`model.hosts` distincte de celle de `mcp.hosts` (jeton `NOORTRACE_TOKEN`
pour le MCP, `NOORTRACE_TOKEN_PASSERELLE` pour la passerelle) et reliée à
elle par un même `host_group` : la corrélation de 5.6 trouve ainsi les
échanges de l'agent. `ANTHROPIC_CUSTOM_HEADERS` ajoute des en-têtes « `Name:
Value` » (R7 F-31) : `X-Noortrace-Run-Id` porte le `run_id` déclaré, retiré
avant le relais. Le relais du jeton de l'hôte vers le fournisseur n'a jamais
lieu : la passerelle le retire et pose la clé de la route.

La passerelle sert `/v1/messages` (flux non tamponné, `ping` relayés,
en-têtes `anthropic-beta` et `anthropic-version` transmis, erreurs amont
inchangées, R7 F-33 à F-36) ; `/v1/messages/count_tokens` et `/v1/models` en
`passthrough` de la route (EX-5.2). Les noms d'outils vus par le modèle sont
`mcp__noortrace__<nom annoncé>` avec `.` → `_` : la connexion d'hôte porte
`tool_name_template: "mcp__noortrace__{tool_announced}"` et
`tool_name_sanitize: true` pour la corrélation (EX-5.22). Un nom complet de
plus de 128 caractères est exclu par Claude Code (R7 F-28) : alias et noms
courts.

#### 19.5.3 Cursor

Fichier `.cursor/mcp.json` (projet) ou `~/.cursor/mcp.json` (global) ; stdio
ou distant par `url` et `headers` ; interpolation `${env:NAME}` (R7 F-44 à
F-47) :

```json
{
  "mcpServers": {
    "noortrace": {
      "url": "http://127.0.0.1:8300/mcp",
      "headers": { "Authorization": "Bearer ${env:NOORTRACE_TOKEN}" }
    }
  }
}
```

Ou, en stdio : `{ "mcpServers": { "noortrace": { "type": "stdio", "command":
"/usr/local/bin/noortrace-connecteur", "args": ["--socket",
"/run/noortrace/mcp.sock"] } } }`. Échanges de modèle : la documentation
officielle de Cursor ne documente aucune option d'URL de base (R7 NV-02) ;
l'enregistreur ne capture que les appels d'outils ; le mode `icap` de la
section 5 est l'alternative si le client dispose d'un mandataire
d'interception. Aucune limite de nombre d'outils n'est publiée par l'éditeur
(R7 NV-01).

#### 19.5.4 SDK Agents d'OpenAI (Python)

Paquet `openai-agents` 0.24.0 (R7 F-52) ; serveur MCP par
`MCPServerStreamableHttp` (ou `MCPServerStdio`) passé à `Agent(mcp_servers=…)`
(R7 F-53 à F-56) ; URL de base du modèle par `OPENAI_BASE_URL` (R7 F-61,
F-62) :

```python
import os
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:8400/v1")
os.environ.setdefault("OPENAI_API_KEY", "jeton-statique-passerelle")

async def main():
    async with MCPServerStreamableHttp(
        name="noortrace",
        params={
            "url": "http://127.0.0.1:8300/mcp",
            "headers": {"Authorization": f"Bearer {os.environ['NOORTRACE_TOKEN']}"},
            "timeout": 10,
        },
        cache_tools_list=True,
    ) as server:
        agent = Agent(name="agent-sinistres", instructions="…", mcp_servers=[server])
        await Runner.run(agent, "Traite le sinistre 2026-77812.")
```

Routes de la passerelle : `/v1/responses` (API par défaut du SDK) et
`/v1/chat/completions` (si `set_default_openai_api("chat_completions")`),
`credentials: "propre"`. `cache_tools_list=True` évite un `tools/list` par
exécution (R7 F-58) ; `list_changed` l'invalide (EX-4.15). Variante
TypeScript (`@openai/agents` 0.21.0) : `MCPServerStreamableHttp({ url, name })`
et `setDefaultOpenAIClient(new OpenAI({ baseURL }))` (R7 F-63 à F-67).

#### 19.5.5 LangGraph / LangChain (Python)

API actuelle `langchain.mcp.MCPAdapter` (`langchain[mcp] >= 1.4.0`, bêta,
`langchain` 1.4.7, `langgraph` 1.2.16 ; le dépôt `langchain-mcp-adapters`
n'est plus maintenu, R7 F-69 à F-75) ; `create_agent` (et non
`create_react_agent`, déprécié, R7 F-79) ; URL de base par
`ChatAnthropic(base_url=…)` ou `ANTHROPIC_BASE_URL`, `ChatOpenAI(base_url=…)` ou
`OPENAI_BASE_URL` (R7 F-80, F-81) :

```python
import os
from fastmcp import Client
from langchain.mcp import MCPAdapter
from langchain.agents import create_agent
from langchain_anthropic import ChatAnthropic

model = ChatAnthropic(model="…", base_url="http://127.0.0.1:8400", api_key="jeton-statique-passerelle")

async def main():
    async with MCPAdapter(Client("http://127.0.0.1:8300/mcp", auth=os.environ["NOORTRACE_TOKEN"])) as adapter:
        tools = await adapter.list_tools()
        agent = create_agent(model, tools)
        await agent.ainvoke({"messages": [("user", "Traite le sinistre 2026-77812.")]})
```

Hors du contexte `async with`, l'adaptateur ouvre une session MCP par appel
d'outil (R7 F-75,
https://docs.langchain.com/oss/python/langchain/mcp/connections) ; dans
l'exemple ci-dessus, le contexte reste ouvert pendant l'exécution.
L'enregistreur ne dépend d'aucun état de session (ère moderne) et tolère les
deux. Avec plusieurs serveurs, `MCPConfig`
(`{"mcpServers": {"noortrace": {"url": …}}}`) préfixe les outils par la clé
de configuration (`noortrace_…`, R7 F-74) : la connexion d'hôte porte alors
`tool_name_template: "noortrace_{tool_announced}"`. Variante JavaScript :
`@langchain/mcp-adapters` 2.x,
`new MCPAdapter({ servers: { noortrace: { url } } })`, `listTools()` (R7 F-82,
F-83).

#### 19.5.6 Autres hôtes (une ligne chacun, formats lus en R7)

VS Code : `.vscode/mcp.json`, objet `servers`, `"type": "http"` + `url` +
`headers`, secrets par `inputs` (R7 F-84) ; Devin Desktop (ex-Windsurf) :
`~/.config/devin/mcp_config.json`, `serverUrl`, limite de 100 outils (R7
F-85) ; Microsoft Agent Framework : `MCPStreamableHTTPTool(name, url,
static_headers)` (R7 F-86) ; Semantic Kernel : `MCPStreamableHttpPlugin` (R7
F-87) ; Google ADK : `McpToolset(StreamableHTTPConnectionParams(url, headers))`
(R7 F-88) ; Gemini CLI : `httpUrl` dans `~/.gemini/settings.json` (R7 F-89) ;
Codex CLI : `[mcp_servers.noortrace]` avec `url` et `bearer_token_env_var`
dans `~/.codex/config.toml` (R7 F-90). Ces hôtes changent de nom et d'URL
(R7 C-14) : chaque page d'intégration publiée porte la date de sa lecture.

### 19.6 Mode ICAP : raccord à un mandataire existant

Pour les hôtes sans URL de base (19.5.1, 19.5.3), le mode `icap` (EX-5.3 à
EX-5.5) se raccorde au mandataire du client. Les éléments à fournir au
client, par équipement, d'après le digest R4 (R4 § 1.2, § 1.3 ; section 5.1
de la présente spécification) : Squid —
`icap_service` REQMOD et RESPMOD vers
`icap://enregistreur:1344/noortrace/reqmod` et `/respmod`, `adaptation_access`
limité aux destinations des fournisseurs, `ssl_bump` déjà en place, et un seul
service par point de vectorisation (un antivirus RESPMOD existant impose un
chaînage) ; Broadcom ProxySG, FortiGate, Check Point : interception SSL
préalable obligatoire, service ICAP sur les seules destinations des
fournisseurs ; dans tous les cas, l'autorité d'interception sur les postes,
l'authentification du lien ICAP (ICAPS avec certificat client, ou liste
d'adresses, EX-5.3), l'en-tête d'adresse cliente que le mandataire doit
transmettre (EX-5.8), et la documentation des limites de 5.1.2 (la réponse en
flux n'est pas bloquable ; corrélation REQMOD/RESPMOD à vérifier, EX-5.4). Le
détail opérationnel est de CT-8 ; l'intégration est à tester en phase 2 sur
Squid, le seul dont la configuration a été lue dans le code source (R4).

## 20. Décisions ouvertes de l'architecture closes par CT-2

**Décision 2 — gestion des clés de l'enregistreur chez le client.** Close
par la section 11 : la clé est Ed25519 (imposé par CT-1), elle ne réside
jamais dans le processus de l'agent ni de l'hôte, et le client choisit une
**classe de garde** selon ce qu'il possède : A (matériel natif Ed25519 par
PKCS#11 `CKM_EDDSA` : Luna, nShield, YubiHSM 2, CloudHSM par mécanisme
propriétaire), B (service de signature : Vault ou OpenBao Transit, AWS KMS,
Google Cloud KMS en niveau logiciel), C (enveloppe : graine chiffrée par un
KMS — y compris Azure Key Vault et Managed HSM, qui n'offrent pas Ed25519 —
ou scellée par un TPM 2.0 sur des PCR), D (fichier, développement
seulement, refusé en production). Justification : l'architecture écrivait
« HSM, KMS ou TPM, choix par client » ; le digest R3 montre que ces trois
mots ne recouvrent pas la même chose pour Ed25519 : certains HSM et KMS
signent nativement (classe A ou B), Azure et les TPM ne le font pas et ne
peuvent protéger qu'une graine (classe C), Nitrokey, Secure Enclave et
StrongBox ne le peuvent pas du tout. Nommer les classes rend le choix
honnête ; la vérification systématique de chaque signature (EX-11.6), la
borne de taille des messages (EX-11.7), la rotation planifiée sans période
imposée et la rotation d'urgence avec rupture de journal quand la clé est
perdue (EX-11.16) sont les conséquences écrites. Ce qui n'est pas réglé par
CT-2 : la cérémonie (CT-7), l'inscription et la révocation au registre
(CT-4), un profil FIPS (hors périmètre, EX-11.11).

**Décision 3 — politique de rédaction des paramètres sensibles avant
hachage.** Close par la section 10 : rédaction **avant** hachage ; jamais de
clair ni de hachage sans clé du clair dans le journal ; une politique JSON
versionnée avec schéma, règles ordonnées (sélecteur par outil et par
pointeur JSON RFC 6901 ou tout texte ; détecteurs IBAN, AVS, carte, adresse,
téléphone, motif nommé, champ ; actions remplacer, pseudonyme à clé,
supprimer ; six portées) ; détecteurs spécifiés au caractère près avec leur
somme de contrôle (MOD 97-10, clé AVS de l'ordonnance du DFI, Luhn) pour que
deux implémentations concordent ; le prompt système rédigé comme toute pièce
; les originaux jamais stockés sauf coffre chiffré hors journal ; la
politique `pii-v1` publiée ; les valeurs en ligne de l'événement (`intent`,
`effects`, `code.model`, délégation déclarée) tirées des seules valeurs
rédigées ou bornées (EX-10.2). Justification : les outils de référence
(Presidio, Google, AWS) convergent sur un petit vocabulaire d'opérations et ne
couvrent pas, ou couvrent sans algorithme publié, les identifiants suisses
(Google a un type `SWITZERLAND_SOCIAL_SECURITY_NUMBER`, R6 § 1.1) ; une
politique déclarative et déterministe est
ce qui rend la rédaction vérifiable (réappliquer la politique redonne les
mêmes octets, EX-10.15) ; le pseudonyme à clé est admis parce que des clients
auront besoin de relier des événements, et dit avec son risque parce que le
CEPD le dit. Ce qui n'est pas réglé : la détection des identifiants hors
table, les homoglyphes, les données encodées, les nombres JSON (10.8).

**Changement apporté à l'architecture — la passerelle devient le mode
nominal du frontal modèle.** L'architecture cible (« Capture : où
l'enregistreur se place », « Déploiement ») ne décrit que l'interception TLS
par le mandataire de sortie du client. CT-2 fait de la **passerelle par
URL de base** le mode nominal (5.1, EX-5.1) et de l'interception TLS (mode
`icap`) l'alternative, pour les quatre raisons de la section 5.1 :
reconfigurer un SDK coûte une variable d'environnement (`ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL`, lues dans le code des quatre SDK, R2) alors que
l'interception coûte trois injections de confiance et un piège Node ; un
flux SSE se relaie sans tampon par une passerelle, pas par ICAP ; la
passerelle est sur le chemin et peut bloquer ; les en-têtes et le corps la
traversent intacts. Le mode miroir est ajouté comme preuve passive. Ce que la
passerelle ne résout pas (hôtes sans URL de base) est dit, et le frontal
MCP capture les appels d'outils dans tous les cas. ARCHITECTURE.md est aligné
en conséquence (section 22).

## 21. Ce que cette version ne couvre pas

- **Ce qui contourne la capture** : un acte de l'agent par un canal qui n'est
  ni MCP ni une API de modèle configurée n'est pas journalisé, et aucun
  dossier ne peut prouver ni cet acte ni son absence. La mise en application
  par le réseau (4.9) réduit cette surface, elle ne la supprime pas.
- **Les formats de modèle de la version 1** : Anthropic sur Google Cloud
  (`rawPredict`, `streamRawPredict`), Amazon Bedrock `InvokeModel`,
  `InvokeModelWithResponseStream` et `Converse`, Gemini, Azure OpenAI API
  datée (5.2) ; les transports non HTTP (WebSocket, temps réel) ; HTTP/2 en
  mode miroir.
- **Les méthodes MCP hors `tools/call`** : relayées hors chaîne (4.5), aucune
  preuve de leur contenu ; la réponse de l'hôte à une elicitation et les
  `inputResponses` MRTR ; les extensions (`tasks`, `ui`).
- **Un démon multi-journal** et le rattachement d'une connexion d'hôte à un
  journal parmi plusieurs (EX-13.7).
- **La corrélation** appel ↔ échange de modèle au-delà de l'heuristique
  déclarée (5.6) ; l'identifiant de requête du fournisseur dans la chaîne.
- **Les détecteurs** hors des cinq nommés (10.8) ; les IBAN hors table ; les
  homoglyphes et formes de compatibilité Unicode ; les données encodées ; les
  nombres JSON ; une politique de rédaction par hôte ou par délégation
  (une seule politique par journal).
- **La relecture périodique des références de secrets** (15.2) et la
  **signature du document de configuration** (18.4).
- **Un profil FIPS** (EX-11.11) ; **l'attestation de clé vérifiée par
  l'enregistreur lui-même** (il la transmet au registre, CT-4).
- **La reprise SSE (`Last-Event-ID`)** et les sessions héritées au-delà de
  ce que 4.7 relaie.
- **La sauvegarde, la restauration, la migration de support, les règles
  d'alerte Prometheus, l'empaquetage `.mcpb`, le déploiement** (CT-8) ; **la
  cérémonie des clés, la revue de sécurité** (CT-7) ; **les règles
  d'approbation et leur évaluation, le cycle de vie des tickets, le mode
  d'attente par défaut, la console** (CT-3) ; **la ligne de commande du
  vérificateur et de l'exportateur** (CT-6) ; **les tests** (CT-9).
- **Les mesures de performance** : des cibles et une méthode (16), aucune
  valeur avant la phase 2.
- **Le mode miroir** n'est construit que si un client l'exige (EX-5.6).
- **Les messages `annulation` et `liberer` du noyau vers le service**, que
  CT-3 §16 propose : en version 0.3, l'annulation par l'hôte d'une requête
  retenue n'est pas transmise au service, et une approbation servie dont le
  relais échoue avant tout événement n'est pas libérée (EX-7.21).
- **Un moteur de correspondance à temps linéaire** dans l'implémentation de
  référence (10.8) : la borne de temps d'EX-10.23 en tient lieu.
- **La corrélation REQMOD/RESPMOD en mode ICAP** sur un mandataire réel
  (EX-5.4) et la **clôture par le stockage** d'un écrivain périmé selon le
  type de volume (EX-13.10) : à vérifier en phase 2.

## 22. Alignement avec le dépôt

Points du dépôt public que cette spécification rend caducs ou complète, avec
l'état attendu. Les fichiers racine (`README.md`, `README.fr.md`,
`ARCHITECTURE.md`, `CHANGELOG.md`) sont alignés dans la même livraison que
CT-2, hors du texte de la spécification.

| Emplacement | Avant CT-2 | Attendu par CT-2 | État |
|---|---|---|---|
| `ARCHITECTURE.md`, « Capture : où l'enregistreur se place », point « Frontière du modèle » | « le proxy de sortie du client. Les appels à l'API du modèle sortent par un proxy HTTPS d'entreprise avec interception TLS » | La **passerelle** par URL de base est le mode nominal (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), l'interception TLS par ICAP l'alternative, le miroir une preuve passive (section 5.1, 20) | fait |
| `ARCHITECTURE.md`, « Déploiement », « les appels à l'API du modèle passent par le proxy de sortie avec interception TLS » | idem | « passent par la passerelle de l'enregistreur, seule autorisée par le pare-feu à joindre les fournisseurs ; à défaut par le mandataire d'interception du client raccordé en ICAP » | fait |
| `ARCHITECTURE.md`, « Journal : comment un événement est écrit », « une clé conservée dans le HSM, le KMS ou la puce TPM du client » | HSM, KMS ou TPM | « une clé Ed25519 gardée selon l'une des classes A à D de CT-2 §11 (matériel, service de signature, enveloppe KMS ou TPM, fichier en développement) » | fait |
| `ARCHITECTURE.md`, « Journal », « segments de fichiers scellés plus une base locale pour la recherche » | base locale pour la recherche | « segments NDJSON en ajout seul (CT-2 §12), pièces sous leur empreinte ; aucune base locale en version 0 » | fait |
| `ARCHITECTURE.md`, « Décisions ouvertes », points 2 et 3 | ouverts | « 2. Close par CT-2 (classes de garde A à D). 3. Close par CT-2 (politique de rédaction v0, `pii-v1`). » ; point 4 : « à régler au prototype » → « close par CT-3 ; CT-2 fixe les deux modes `retenir` et `erreur` » | fait |
| `ARCHITECTURE.md`, « Modèle de menace », ligne « L'enregistreur lui-même est compromis » | « Clé en HSM, KMS ou TPM » | « Clé selon la classe de garde ; vérification de chaque signature ; copies WORM ; rotation d'urgence (CT-2 §11, §18) » | fait |
| `ARCHITECTURE.md`, « Journal : comment un événement est écrit » | seule la clé Ed25519 est nommée | ajouter la **clé de chaîne** (secp256k1) sous laquelle chaque clé Ed25519 est inscrite au registre, qui signe les ancres et relaie les clôtures, une par clé Ed25519 (EX-11.19) | fait |
| `spec/README.md`, table des spécifications, ligne CT-2 | « Enregistreur \| à écrire \| décisions 2 et 3 » | « [Enregistreur](CT-2-enregistreur.md) \| version 0.2, en revue \| décisions 2 et 3 » | fait |
| `spec/README.md`, table des schémas | trois schémas | ajouter `configuration-enregistreur-v0.schema.json` (CT-2 §15, référence `politique-redaction`) et `politique-redaction-v0.schema.json` (CT-2 §10) ; commande `ajv` avec `-r` pour le couple | fait |
| `spec/README.md`, section « Vecteurs de test » | `vecteurs/ct-1/` seulement | ajouter `vecteurs/ct-2/` (annexe B) : publiés, produits par `scripts/vecteurs/generer-ct2.mjs` (`npm run vecteurs:ct2`), rejoués par `test/enregistreur.test.js`, confrontés par le module Go séparé `spec/vecteurs/ct-2/verificateur-independant` | fait |
| `package.json`, `scripts` | `vecteurs:ct1`, `verify:dossier`, … | ajouter `vecteurs:ct2`, `mesures:ct2` (16.2), `demo:up` (`docker compose -f demo/compose.yaml up`) ; dépendances de développement inchangées en version 0 (le générateur n'emploie que `node:crypto` et `ethers`) | fait pour `vecteurs:ct2`, sans nouvelle dépendance ; `mesures:ct2` et `demo:up` en phase 2 |
| `.github/workflows/ci.yml`, tâche `vecteurs` | régénère `spec/vecteurs/ct-1` et lance le Go | tâche renommée « CT-1 and CT-2 vectors, two independent implementations » ; régénérer aussi `spec/vecteurs/ct-2` avec `git diff --exit-code`, lancer le vérificateur Go de `ct-2` (`gofmt`, `go vet`, `go test`, `go run . ..` ; annexe B, familles `jcs-integral`, `redaction`, `pieces-mcp`, `pieces-modele`, `evenements`) ; valider les deux schémas et leurs exemples (`pii-v1` de 10.9, configuration de 15.3) par les tests, avec `validerSchema` de `scripts/lib/journal.mjs`, sans nouvelle dépendance ; une tâche `demo` qui lance `docker compose` et exige le code de retour `0` du vérificateur sous deux minutes | fait pour la régénération de `ct-2`, le vérificateur Go de `ct-2` et la validation des exemples par schéma ; tâche `demo` en phase 2 |
| `README.md` (anglais, public) | promesse, démonstration à venir | section « Run the demo » (`docker compose up`), section « Integrations » (cinq hôtes, chacun « tested in phase 2 »), section « What it does not prove » reprenant CT-1 §15 et 5.8 ; aucune mention des documents internes | fait pour la capture, le statut et ce que le projet ne voit pas ; « Run the demo » et « Integrations » ajoutées quand la démonstration et les intégrations existeront (phase 2) |
| `CHANGELOG.md` | CT-1 | entrée « CT-2 — Enregistreur, version 0.2 : spécification, deux schémas, vecteurs, implémentation de référence JavaScript et vérificateur Go indépendant » | fait |
| `scripts/lib/journal.mjs` | JCS v0 (`canonicaliserJCS`, entiers seulement) | ajouter `canonicaliserJCSIntegral` (RFC 8785 complet, nombres par `Number::toString`) pour les pièces, distinct de la forme v0 ; les deux coexistent (section 8) | fait |
| `spec/vecteurs/ct-2/verificateur-independant/` | vérificateur Go de `ct-1` seulement | décision : module Go séparé `noortrace-ct2`, qui recalcule les familles de l'annexe B (JCS intégral, détecteurs, formes consolidées, chaîne `evenements`) ; le module de `spec/vecteurs/ct-1/verificateur-independant/` reste inchangé, les vecteurs CT-1 aussi | fait |

Révision 0.3 :

| Emplacement | Avant la révision 0.3 | Attendu par la révision 0.3 | État |
|---|---|---|---|
| `spec/README.md`, table des spécifications, ligne CT-2 | « version 0.2, en revue » | « version 0.3, en revue » | fait |
| `spec/README.md`, table et commande des schémas de CT-2 | deux schémas chargés ensemble | trois : `configuration-enregistreur-v0`, `politique-redaction-v0`, `politique-approbation-v0` (`$ref` de `policy.approval.rules`), commande `ajv` avec deux `-r` | fait |
| `spec/schemas/configuration-enregistreur-v0.schema.json` | `rules` « opaque pour CT-2 » ; `mode` décrit avec `-32015` | `rules` désigné par `$ref` vers `politique-approbation-v0` ; `mode` requis, sans valeur par défaut (`erreur` dans la configuration de référence) ; `storage.relay_mac_key` (EX-7.22) ; `limits.redaction_budget_ms` entier d'au moins 1 (EX-10.23) ; quotas `received_bytes_per_minute` et `redaction_ms_per_minute` (EX-4.47) | fait |
| `spec/CT-3-approbations.md`, §15.2 et renvois | lignes de CT-2 « à faire » ou « à proposer » ; `-32015` | « fait (CT-2 0.3) », propositions adoptées avec leur EX ; signal d'approbation (EX-4.49) au lieu de `-32015` ; consommation tardive (T22) ; continuations MRTR (3.2, 14) | fait |
| `spec/schemas/politique-approbation-v0.schema.json`, `spec/schemas/ticket-v0.schema.json` | « opaque pour CT-2 » ; `check` de `$defs/cas_remise` limité à `SG-1` à `SG-6` ; `ouvrir` décrit sans `request_event` ni `arguments_piece` | descriptions alignées ; `SG-7` admis dans `cas_remise` (EX-7.5) | fait |
| `scripts/lib/capture.mjs`, `scripts/lib/approbation.mjs` | codes `-32010` à `-32017` ; `-32015` pour l'attente ; `erreursMotifRE2` sans règle de structure ; `limits.redaction_budget_ms` non appliqué ; `extract` compilé sans réécrire `(?P<` | codes de la table de 4.4 ; signal d'approbation (EX-4.49) ; règles a) à c) et point 5 d'EX-10.6, réécriture des seules ouvertures `(?P<nom>` ; budget d'EX-10.23, opérations 1 à 4, refus avant relais ; quotas d'EX-4.47 ; `requesters` dans `charger` ; SG-7 ; RL-1 à RL-4 et continuations MRTR ; réponse d'`evaluer` sans ordre des membres et jeu exploitable ; rédaction du motif (EX-10.24) ; consommation tardive (CT-3 T22) | fait |
| `scripts/vecteurs/generer-ct2.mjs`, `generer-ct3.mjs`, vecteurs `ct-2` et `ct-3`, vérificateurs Go | codes `-3201x` dans `pieces-mcp` et `journal-demo` ; motifs refusés sans les formes d'OWASP ; cas `separation-non-verifiee-par-le-noyau` valide | codes de la table de 4.4, `result_rendered_seq_5`, cas d'approbation de `pieces-mcp`, motifs d'EX-10.6 avec `matches` (annexe B) ; cas SG-7 invalide ; trace `consommation-tardive` | fait |
| `CHANGELOG.md` | entrée CT-2 version 0.2 ; entrée CT-3 : « an error carrying the ticket » | entrée CT-2 version 0.3 (alignement sur CT-3, codes hors de la plage héritée et signal d'approbation, `-32015` retiré sans successeur, contrôle des motifs et budget de rédaction, vérificateurs Go) ; entrée CT-3 : « the proxy answers at once with a tool error result (`isError`) carrying the ticket and its state (`erreur` mode) by default » et le décompte du vérificateur Go de `ct-3` | fait |
| `ARCHITECTURE.md`, « Approbation : avant l'action, pas après », dernier paragraphe ; `README.md`, ligne CT-3 | « répond aussitôt par une erreur qui porte le numéro de ticket » ; « an immediate error carrying the ticket » | « répond aussitôt par un résultat d'erreur d'outil (`isError`) qui porte le numéro de ticket et son état (mode `erreur`, par défaut, CT-3 §11) » ; « an immediate tool error result (`isError`) carrying the ticket and its state by default » | fait |

## Annexe B — Disposition des vecteurs `spec/vecteurs/ct-2`

Les vecteurs sont publiés avec CT-2, comme ceux de CT-1 l'ont été avec CT-1 :
produits par `scripts/vecteurs/generer-ct2.mjs` (`npm run vecteurs:ct2`),
rejoués par `test/enregistreur.test.js`, et confrontés par le vérificateur Go
indépendant du module séparé `spec/vecteurs/ct-2/verificateur-independant`
(`noortrace-ct2`) ; le module de `ct-1` reste inchangé. Leur index,
`spec/vecteurs/ct-2/INDEX.md`, est généré.
Tout est **déterministe** : clés de test de CT-1 §13 (`rec-test-01`,
`rec-test-02`, comptes Hardhat 1 à 3), horodatages fixes, identifiants fixes,
clé de pseudonymisation de test publique. Les vecteurs CT-1 (`ct-1/`) ne
changent pas. Les clés JSON sont en anglais, les descriptions en français.
Chaque répertoire porte un `attendu.json` qui dit ce qu'un lecteur conforme
doit obtenir ; un `INDEX.md` à la racine décrit les cas.

Constantes propres aux vecteurs CT-2 :

| Grandeur | Dérivation | Valeur |
|---|---|---|
| Organisation | `assureur-demo`, `org_id = keccak256(UTF-8("assureur-demo"))` | `0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab` (CT-1 §13) |
| Journal | `journal-demo`, `journal_id = keccak256(UTF-8("journal-demo"))` | calculée par le générateur, imprimée dans `INDEX.md` |
| Nonce période N | `SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/journal-demo/periode-N"))` | idem |
| Clé de pseudonymisation de test | `SHA-256(UTF-8("noortrace/vecteurs/v0/cle-pseudonyme/test"))` | `0x139011dc372b3ce979a162b0dee18753e67e1477ea4db3c55f929829c2ca3808` |
| Période de démonstration | `[1794304800, 1794308400)` = 2026-11-10T10:00:00Z → 11:00:00Z | — |
| Version de l'enregistreur | `code.recorder` | `"0.1.0"` |

### B.1 Arborescence

```text
spec/vecteurs/ct-2/
  INDEX.md
  jcs-integral/
    cas.json
  redaction/
    politique-pii-v1.json
    politique-pseudonyme-test.json
    politique-regles-test.json
    motifs.json
    cas.json
  pieces-mcp/
    appels/<nom-du-cas>/
      hote.jsonl
      amont.jsonl
      attendu.json
    agregation/
      serveurs.json
      attendu.json
      normalisation/            (serveurs.json, attendu.json)
      sans-prefixe/             (idem)
      sans-prefixe-un-serveur/  (idem)
  pieces-modele/
    <fournisseur>-<cas>/
      requete.json           ou  requete.brut  (requête non analysable)
      requete-entetes.json
      reponse.json (hors flux)  ou  reponse.sse  (flux)   — absents pour un refus
      reponse-entetes.json                                 — absent pour un refus
      attendu.json
  evenements/
    journal-demo/
      evenements.json
      attendu.json
      pieces.json
      cles.json
      segment.ndjson
      intentions.ndjson
      politique.json
      entrees.json
      dossier-seq-7/          (dossier CT-1 v0 de seq 7 et son attendu.json)
  verificateur-independant/   (module Go propre ; hors générateur)
```

Le générateur n'écrit que les entrées listées (il les efface et les réécrit)
et laisse le reste du répertoire tel quel, comme `generer-ct1.mjs`.

### B.2 `jcs-integral/cas.json`

Tableau d'objets `{ "name", "input", "canonical", "note" }` :

| Champ | Règle |
|---|---|
| `name` | identifiant du cas, `^[a-z0-9-]+$`, unique |
| `input` | **texte JSON** (chaîne) tel qu'il serait reçu : nombres avec fractions, exposants, zéros, grands entiers, chaînes avec échappements |
| `canonical` | la forme canonique **JCS intégral** (chaîne), ou `null` si l'entrée est invalide (`NaN`, `Infinity` écrits en texte, clé en double, substitut isolé) |
| `note` | français, libre |

Cas obligatoires : les 24 lignes finies des 26 lignes de la table de
l'annexe B de la RFC 8785 (l'entrée est le texte JSON de la colonne « JSON
Representation », ou une forme équivalente non canonique — `1E+21`,
`0.000001000`, `1.0` — et la sortie la colonne elle-même ; `NaN` et `Infinity`
donnent `null`) ; les cas limites de CT-1 §4 qui restent valides en JCS intégral
(`{"a":1.0}` → `{"a":1}`, `{"a":1e3}` → `{"a":1000}`, `{"a":9007199254740993}` →
une valeur qui **n'est pas** l'entrée : `{"a":9007199254740992}`, ce qui
documente la perte de précision au-delà de 2^53, RFC 7493 § 2.2) ; les cas
invalides de CT-1 §4 qui le restent (`{"a":1,"a":2}`, `{"a":"\ud800"}`) ; le tri
des clés par unités UTF-16 ; les contrôles échappés en minuscules.

### B.3 `redaction/`

`politique-pii-v1.json` : le document de la section 10.9, octets identiques à
l'exemple imprimé (plus un saut de ligne final, validé contre le schéma).

`politique-pseudonyme-test.json` : la politique `pii-v1` avec `name:
"pii-pseudo-test"`, sa propre `description`, `pseudonym_key: {"env":
"NOORTRACE_VECTEURS_CLE_PSEUDO", "encoding": "hex"}` (la clé de test, en
hexadécimal, est donnée dans `INDEX.md` et dans l'en-tête de cette annexe),
`action: {"kind": "pseudonyme"}` sur chaque règle, et, **en tête** des règles,
la règle `champ` suivante, qui pseudonymise une chaîne désignée par pointeur
(EX-10.11) :

```json
{"id":"iban-champ","description":"IBAN du beneficiaire designe par pointeur : pseudonyme calcule sur la chaine elle-meme.","scopes":["arguments"],"tools":"*","path":"/iban_beneficiaire","detectors":[{"type":"champ","label":"iban"}],"action":{"kind":"pseudonyme"}}
```

`politique-regles-test.json` (`name: "pii-regles-test"`) : porte les cas
obligatoires que `pii-v1` ne peut pas porter (elle n'a ni `path`, ni
`champ`, ni motif nommé appliqué) : sélecteurs par pointeur JSON, détecteur
`champ` avec `remplacer` et `supprimer`, motif nommé, règles enchaînées,
règles dont l'ordre exige un second passage (EX-10.14), puis les cinq
détecteurs.

`motifs.json` : tableau d'objets `{ "pattern", "admis", "note" }`, avec,
pour certains motifs admis, un membre `matches` : `[ { "input", "first" } ]`,
la première correspondance (leftmost-first, correspondance entière) du motif
dans chaque texte, ou `null` ; ce sont des motifs
du sous-ensemble commun ECMAScript/RE2 d'EX-10.6 (`admis: true`) et des
motifs refusés (`admis: false` : `.`, `\s`, `\u…`, `\x{…}`, `\p{…}`, `\A`,
classe POSIX, recherche avant, drapeau, quantificateur possessif, référence
arrière, borne au-delà de 1 000, classe vide, quantificateur sur une
frontière). Depuis la version 0.3, les refusés comprennent aussi les quatre
motifs d'OWASP `^(a+)+$`, `([a-zA-Z]+)*$`, `(a|aa)+$` et `(a|a?)+$`, un
quantificateur borné sur une alternative (`(a|aa){1,1000}$`), une répétition
imbriquée bornée (`(a{1,1000}){1,1000}$`), une alternative qui se recouvre
sous répétition (`(\w|\d)+$`), une forme bénigne refusée par la règle a)
(`(?:[0-9]{4} ?){3}`), un groupe quantifié qui peut être vide (`(?:\b)+x`)
et un motif de taille développée 1 001 (`[0-9]{1000}x`), chacun avec la
règle a), b) ou c) qui le refuse dans `note` ; les admis comprennent un
motif à retour arrière polynomial (`[0-9]+$`), avec la note qu'EX-10.23 le
borne, et un groupe nommé de la forme `(?P<nom>…)`. Depuis la même
version, les admis comprennent aussi quatre motifs où « (?P< » n'ouvre pas de
groupe nommé ou en ouvre un après une barre oblique inverse échappée
(`[(?P<]x`, `a\(?P<b`, `\(?P<x>`, `\\(?P<x>a)`), chacun avec `matches`
(EX-10.6 : seules les ouvertures reconnues par l'analyse sont réécrites), et
les refusés trois quantificateurs à zéro non significatif (`a{01}`,
`[0-9]{04}`, `a{0,01}`). Aucun cas n'a d'attendu de durée.

`cas.json` : tableau d'objets :

| Champ | Règle |
|---|---|
| `name` | identifiant du cas |
| `policy` | `"pii-v1"`, `"pii-pseudo-test"` ou `"pii-regles-test"` |
| `scope` | une des six portées |
| `tool` | nom annoncé ou `null` |
| `input` | la valeur JSON de la pièce avant rédaction ; une chaîne est toujours une pièce texte (`prompt_systeme`, contexte `text/plain`) |
| `expected.piece` | les octets de la pièce stockée, en chaîne UTF-8 (JCS intégral de la valeur rédigée, ou le texte) |
| `expected.sha256`, `expected.length`, `expected.redacted` | la référence CT-1 §5.4 de la pièce ; `expected.media_type` (`text/plain`) pour une pièce texte |
| `expected.matches` | tableau `[{ "rule", "detector", "count" }]` : ce que le journal d'exploitation compte (EX-10.17), additionné sur les passages, sans les détecteurs qui n'ont rien trouvé ; `detector` vaut le type du détecteur (`iban`, `avs`, `carte`, `email`, `telephone`, `regex`, `champ`) |

Cas obligatoires : un cas valide et un cas invalide (somme de contrôle fausse)
pour chacun des cinq détecteurs, en forme compacte et en forme avec
séparateurs ; les onze pays de la table IBAN (un IBAN valide chacun, construit
par le générateur avec la méthode de génération de 10.3.2) ; un IBAN d'un
pays hors table (non rédigé) ; une adresse avec partie locale de 64 octets
et une de 65 (non rédigée) ; une adresse suivie d'un point final et une
suivie d'un trait d'union (rédigées, 10.3.5) ; une adresse longue (cas
`email-long`, EX-10.23) ; un numéro de téléphone à 15 chiffres et un à 16
(non rédigé), deux numéros collés (EX-10.9) et les groupes entre
parenthèses de 10.3.6 ; les deux exemples de 10.9 ; un cas `path` + `champ`
avec `remplacer` sur un nombre JSON ; un cas `supprimer` sur un membre et
sur un élément de tableau ; un cas de motif nommé ; un cas où plusieurs
règles s'enchaînent ; un cas qui exige un second passage (EX-10.14) ; un
jeton opaque qui ressemble à une carte (EX-10.9) ; un cas d'idempotence
(l'entrée est une pièce déjà rédigée : `expected.redacted = false`, octets
identiques) ; un cas par portée ; un cas `prompt_systeme` ; un cas de
pseudonyme par détecteur avec `pii-pseudo-test`, et un cas de pseudonyme
`champ` sur une chaîne. Réappliquer la politique à `expected.piece` redonne
les mêmes octets (EX-10.15).

### B.4 `pieces-mcp/`

**`appels/<cas>/`** — un `tools/call` reçu d'un hôte. `hote.jsonl` : les
messages JSON-RPC échangés avec l'hôte, dans l'ordre, un par ligne, chacun
dans une enveloppe
`{"dir":"in"|"out","t":"<horodatage>","line":"<texte tel quel>"}` (`in` : reçu
de l'hôte ; `out` : rendu à l'hôte ; `line` est une chaîne, pour que ses octets
soient exacts : une ligne stdio, ou le corps d'un POST quand `transports.host`
vaut `http`). `hote.jsonl` commence par l'échange `tools/list` qui sert la liste
à cette connexion d'hôte (EX-4.13, EX-4.45), puis porte la requête reçue et la
réponse rendue. `amont.jsonl` : de même pour le serveur d'outils (`out` : envoyé
au serveur, `in` : reçu de lui), y compris la sonde `server/discover`, la
poignée de main `initialize`, une annulation ou une réponse tardive ;
l'enveloppe `{"dir":"in","t":"<horodatage>","eof":true}` marque la fin de
fichier sur la sortie standard d'un serveur stdio. `attendu.json` :

```json
{
  "tool_announced": "demo__payments.create",
  "tool_original": "payments.create",
  "server_alias": "demo",
  "class": "ecriture",
  "rejected": false,
  "pieces": {
    "arguments": { "sha256": "0x…", "length": 0, "redacted": true, "bytes": "…" },
    "result":    { "sha256": "0x…", "length": 0, "redacted": false, "bytes": "…" },
    "definition": { "sha256": "0x…", "length": 0, "redacted": false, "media_type": "application/json", "bytes": "…" },
    "definition_current": null,
    "list": { "sha256": "0x…", "length": 0, "redacted": false, "media_type": "application/json", "bytes": "…" }
  },
  "context": [ { "sha256": "0x…", "length": 0, "redacted": false, "media_type": "application/json", "kind": "autre" } ],
  "is_error": false,
  "duration_ms": 412,
  "error_rendered": null,
  "approval": null,
  "result_rendered": null,
  "protocols": { "host": "2026-07-28", "server": "2026-07-28" },
  "transports": { "host": "stdio", "server": "stdio" },
  "note": "…"
}
```

`bytes` porte les octets de la pièce en chaîne UTF-8. `definition` est la
définition servie (celle de la liste de `hote.jsonl`), `definition_current` la
définition courante quand elle diffère (sinon `null`), `list` la pièce « liste
annoncée » ; `context` suit EX-4.45 ; la classe vient de la définition
courante. `duration_ms` = `t_reponse − t_envoi`, `t_reponse` suivant EX-4.48
pour une issue sans réponse. Un refus au pas 1 de 4.4 a `rejected: true`,
`tool_announced`, `tool_original`, `server_alias`, `class`, `pieces`,
`is_error` et `duration_ms` à `null`, `context: []`, un `amont.jsonl` vide, et
`error_rendered` = l'erreur rendue. `approval` est `null`, ou, pour un cas
d'approbation, `{ "response": <réponse d'evaluer simulée, $defs/reponse_evaluer
de ticket-v0> }` ; `result_rendered` est `null`, ou le résultat que
l'enregistreur rend lui-même (EX-4.49), objet JSON dont la ligne rendue de
`hote.jsonl` porte les octets ; pour un cas d'approbation sans relais,
`amont.jsonl` est vide, `pieces.result`, `is_error` et `duration_ms` sont
`null`, et `pieces.arguments` est la pièce « arguments » écrite au pas 4.
Les cas d'approbation sont rendus dans le mode d'attente `erreur`, celui de
la configuration de référence (CT-3 EX-11.1 ; 4.4 pas 6) : le signal
`en_attente` est rendu aussitôt ; le refus sans ticket (pas 5) ne dépend pas
du mode ; `attendu.json` ne porte pas de membre `mode`. `protocols.host` est
la version vue côté hôte (`_meta` de la requête, sinon réponse à
`initialize`), `protocols.server` celle de la connexion au serveur de
l'alias, lue dans `amont.jsonl` ; quand `amont.jsonl` est vide (refus au pas
1, cas d'approbation sans relais), `protocols.server` est la version
déclarée du serveur configuré, qu'aucune transcription ne porte : elle est
déclarative et n'est pas vérifiable ; `transports.server` l'est de même. Les
cas peuvent porter `timeout_ms` (délai de l'outil) et
`limits.response_max_bytes`. Cas obligatoires : appel exécuté sans erreur
(`execute-ecriture`, l'appel de seq 7 de `journal-demo`) ; résultat `isError:
true` ; erreur JSON-RPC du serveur (pièce `noortrace_jsonrpc_error`) ; délai
(`-31011`) ; serveur injoignable après l'envoi (`-31014`, fin de fichier) ;
taille dépassée (`-31013`) ; refus par la politique sans ticket
(`approbation-refus`, hôte moderne : le résultat exact d'EX-4.49) ; ticket en
attente (`approbation-en-attente`, hôte hérité : le signal sans `resultType`) ;
`resultType: "input_required"` ; hôte hérité vers serveur moderne et l'inverse
(les `_meta` réécrits) ; arguments avec des nombres non entiers exactement
représentables (EX-4.20) ; refus d'un nombre non représentable et d'un nombre
hors de la double précision (EX-4.44) ; ligne avec un CR (EX-4.43) ; lot
(EX-4.3) ; blancs non significatifs ; corps HTTP sur plusieurs lignes relayé à
un serveur stdio (EX-4.43) ; résultat qui n'est pas un objet (4.4 pas 12) ;
`id` entier au-delà de 2^53 (4.4 pas 14) ; définition servie différente de la
définition courante (EX-4.45).

**`agregation/`** — `serveurs.json` : tableau de serveurs fictifs `{ "alias",
"tools": [ { "name", "annotations" } ] }` ; `attendu.json` : `{ "prefix",
"page_size", "normalisations" (facultatif : `[{ "template", "sanitize" }]`
des connexions d'hôte), "announced": [ { "server_alias", "original",
"announced", "class", "definition_sha256" } ], "rejected": [ { "server_alias",
"original", "reason" } ], "pages": [[…]] }`, `reason` étant l'une des valeurs
fixes d'EX-4.11 (`nom_reserve`, `nom_invalide`, `collision`,
`x_mcp_header`). Cas : préfixe `__`, nom avec point, outil `noortrace.x`
rejeté, nom annoncé de 129 caractères rejeté (128 admis), collision dans un
serveur, classe par `readOnlyHint`, ordre déterministe et pagination par
100 ; sous-répertoires de même forme : `normalisation/` (collision après
gabarit et normalisation, EX-4.11 règle 3), `sans-prefixe/` (`prefix: false`
et deux serveurs : refus de configuration, `configuration_refusee: true`) et
`sans-prefixe-un-serveur/`.

### B.5 `pieces-modele/`

Un répertoire par cas, nommé `<fournisseur>-<cas>` :
`anthropic-messages-non-flux`, `anthropic-messages-flux`,
`anthropic-messages-flux-outil`, `anthropic-messages-flux-bom`,
`anthropic-messages-flux-incomplet`, `anthropic-messages-erreur-http`,
`anthropic-messages-reponse-non-json`,
`anthropic-messages-requete-non-analysable`, `openai-chat-non-flux`,
`openai-chat-flux`, `openai-chat-flux-outils`, `openai-chat-prompt-inline`,
`openai-responses-flux`, `openai-responses-flux-incomplet`,
`bedrock-mantle-non-flux` (même corps qu'Anthropic, libellé `bedrock-mantle`).

| Fichier | Contenu |
|---|---|
| `requete.json` | le corps JSON de la requête **telle que reçue** (mise en forme libre : les octets exacts n'importent pas pour la pièce, qui est en JCS intégral après rédaction) |
| `requete.brut` | à la place de `requete.json`, pour une requête non analysable : les octets reçus |
| `requete-entetes.json` | les en-têtes de la requête `{ "anthropic-version": "…", … }`, sans aucun en-tête d'authentification |
| `reponse.json` | hors flux : le corps reçu (octets exacts ; pas forcément du JSON) |
| `reponse.sse` | en flux : la **transcription SSE**, fichier texte brut, **octets exacts** du corps de la réponse amont tel que l'analyseur de 5.4.1 le lit : UTF-8 (une marque d'ordre d'octets initiale seulement dans le cas `-flux-bom`), fins de ligne `\n` (LF seul, le format d'Anthropic et d'OpenAI dans leurs exemples documentés, R2 F-A27, F-O13), événements séparés par une ligne vide, lignes `event:` et `data:` telles quelles, commentaires `: …` et événements `ping` inclus là où le cas les prévoit, aucune modification, aucun saut de ligne ajouté en fin de fichier au-delà de celui de la dernière ligne vide. Le générateur écrit ce fichier avec `writeFileSync(buffer)` et le vérificateur le lit en octets. |
| `reponse-entetes.json` | `{ "status", "content-type", … }` : le statut HTTP et le `Content-Type` reçus (avec ses paramètres éventuels), qui décident du traitement (5.3.1 pas 5), et l'identifiant de requête du fournisseur |
| `attendu.json` | `{ "format", "provider_label", "route", "status", "options": { "prompt_in_request", "prompt_system" }, "refused": null ou { "status", "reason", "body" }, "consolidated": <forme consolidée, valeur JSON, ou null hors flux>, "pieces": { "request": réf+bytes, "response": réf+bytes, "system_prompt": réf+bytes ou null, "intent": réf+bytes ou null } ou null, "code_model": "…", "prompt_version": "0x…" ou null, "intent": "…" ou référence ou null, "tool_calls": [ { "id", "name", "arguments" } ], "is_error": false, "incomplete": false, "note" }` |

Les réponses des cas `anthropic-*` reproduisent la séquence documentée
(message_start, blocs, deltas avec premier `partial_json` vide, `message_delta`
avec `stop_reason` et `usage` cumulatif, `message_stop`, un `ping`) ; les cas
`openai-chat-*` les chunks `data:` sans `event:` avec `data: [DONE]` et un
chunk final `usage` ; les cas `openai-responses-*` les événements typés
jusqu'à `response.completed`. Les cas `*-incomplet` s'arrêtent avant
l'événement terminal : `consolidated` porte `noortrace_flux_incomplet: true`
et `is_error: true`. Le cas `-requete-non-analysable` est un refus (EX-5.7) :
`refused: {"status": 400, "reason": "corps_non_analysable", "body": <corps
d'erreur au format du fournisseur>}`, `pieces: null`, ni réponse ni
événement. Le cas `-reponse-non-json` a un statut 200 et un `Content-Type`
qui n'est pas JSON : pièce non JSON (EX-8.7), `is_error: true`.
`openai-chat-prompt-inline` emploie `prompt_in_request: "inline"` (EX-8.5).

### B.6 `evenements/journal-demo/`

La courte exécution de démonstration de 19.2 sous l'ensemble de politique
de la version 0.2 de CT-2, antérieur à CT-3, **chaînée avec les clés de
test de CT-1** et vérifiable par les outils de CT-1 (`verifierChaine` de
`scripts/lib/journal.mjs`, famille « journaux » du vérificateur Go), dans la
disposition de `ct-1/journal-valide/` :

| Fichier | Contenu |
|---|---|
| `evenements.json` | les huit événements de 19.2 (`seq` 1 à 8 : politique, échange, lecture, échange en flux, retenue, décision, écriture relayée, échange), complets, mis en forme ; `recorder_key_id` `rec-test-01` ; `ts` fixes dans la période de démonstration |
| `attendu.json` | `{ "valide": true, "diagnostics": [], "events": [ { "seq", "tool", "hash", "sig", "prev_hash", "canonical_length" } ], "A": {…}, "D_A": "0x…", "policy_version", "policy_sha256", "policy_length", "intention_sha256", "intent_id", "segment_sha256", "segment_length", "result_rendered_seq_5", "correlation": { "host_group", "run_id", "window_ms", "tool_name_template", "tool_name_sanitize", "calls": [ { "seq", "exchange_seq", "tool_call_id", "inherits_from_seq", "intent" } ] }, "period": {…} }` |
| `pieces.json` | les pièces référencées : `[ { "sha256", "length", "redacted", "media_type", "bytes" } ]`, dont les pièces de définition d'outil et la pièce « liste annoncée », les pièces « requête », « réponse », « prompt système », « intention », « arguments », « résultat » et le document d'ensemble de politique |
| `cles.json` | `cles.json` du dossier (CT-1 §11.2) pour `rec-test-01` |
| `segment.ndjson` | le segment tel que l'enregistreur l'écrit (12.2) : en-tête (`epoch: 1`, `first_seq: 1`) puis les huit lignes JCS v0, octets exacts |
| `intentions.ndjson` | le journal d'intention de l'époque 1 : la ligne intention de `seq 7` (EX-12.12, neuf clés, `intent_id` `i-00000000000000000001-000000000001`), sa ligne contexte et sa levée |
| `politique.json` | l'ensemble de politique, antérieur à CT-3, qu'avait la démonstration de la version 0.2 (dont `redaction` = `pii-v1`), tel que haché pour `policy_sha256` de `seq 1` ; il porte sous `approval.rules` un tableau illustratif et non un document `politique-approbation-v0`, et il reste figé (voir ci-dessous) : ce n'est pas le membre `policy` de `demo/configuration-demo.json` (19.1) |
| `entrees.json` | les entrées brutes de la démonstration : `host` (l'entrée de connexion d'hôte `agent-demo` : `id`, `host_group`, `launched_by`, `on_behalf_of`, `scope`, `tool_name_template`, `tool_name_sanitize`), `exchanges` (`seq`, `host`, `host_group`, `run_id`, `format`, `provider_label`, `route`, `t_complet`, `request`, `response_content_type`, `response_body`), `calls` (`seq`, `host`, `host_group`, `run_id`, `t_recu`, `host_line`, `inherits_from_seq`) et `served_list` (la liste servie à la connexion) |
| `dossier-seq-7/` | le dossier CT-1 v0 de l'appel d'écriture relayé (seq 7) et son `attendu.json` |

`result_rendered_seq_5` est le signal d'approbation rendu pour l'appel
retenu de `seq 5` en mode `erreur` (EX-4.49), l'objet `result` de la ligne
rendue ; il remplace `error_rendered_seq_5` (`-32015`) de la version 0.2.
Aucun événement de `journal-demo` ne change. `politique.json` reste figé :
le remplacer par une politique conforme à CT-3 changerait `policy_sha256`
et, avec lui, les huit événements, le segment, le journal d'intention, les
pièces et le dossier de `seq 7`, pour une vérification que CT-3 ne demande
pas sur ce vecteur (CT-3 4.1). Il est donc validé contre `$defs/policy_set`
du schéma de configuration **hors** `approval.rules`, qui est vérifié comme
un tableau, et il n'est pas soumis à la validation d'EX-15.4 pas 3 : c'est
un vecteur de hachage, pas une configuration de démarrage. Le fichier
`approbations.json` de `dossier-seq-7/` garde sa `source` libre et l'ordre
de ses membres, que CT-1 v0 admet (CT-1 §11.2), sans la forme de CT-3
EX-8.8.

Le vérificateur Go recalcule, pour cette famille : `hash` et `sig` de chaque
événement (CT-1 §6), la chaîne (C-1 à C-3), les références de pièces (E-6
avec `pieces.json`), `policy_sha256` depuis `politique.json` en JCS intégral,
la pièce « arguments » de `seq 7` depuis `pieces-mcp` par réapplication de la
politique (EX-10.15), les pièces, `intent`, `code.model` et
`code.prompt_version` des échanges depuis `entrees.json`, la corrélation
des appels (EX-5.22, sur les valeurs en clair d'`entrees.json`) et la
reprise de `seq 5` par `seq 7` (EX-7.12), le `context` des appels (EX-4.45),
les effets évalués sur les valeurs rédigées (EX-7.6), l'`intention_sha256`
et la forme de la ligne intention depuis `intentions.ndjson`, et l'égalité
octet par octet de `segment.ndjson` avec l'en-tête attendu et les lignes JCS
v0 des événements.

### B.7 `INDEX.md`

Généré ; liste chaque famille, chaque cas et son attendu en une ligne, dans
la forme de `ct-1/INDEX.md`, et imprime les constantes de l'en-tête de cette
annexe (`journal_id`, nonces, clé de pseudonymisation de test) calculées par
le générateur.

## Annexe C — Sources des faits externes

Les renvois R1 à R9 du texte désignent les notes de recherche internes du lot
CT-2 (les « digests »), et R10 celle de la révision 0.3 (0.1), qui ne sont
pas publiées. Cette annexe donne, pour
chaque renvoi de la présente spécification, l'objet du fait en quelques mots
et la ou les sources primaires publiques consultées, à la date indiquée ; elle
ne remplace pas la lecture de ces sources. Un fait marqué « non vérifié » dans
le texte le reste : pour un point non vérifié (NV-…, N2.…), la source indiquée
est la page lue, qui ne tranche pas le point. Formes des renvois : Qn
(question), F-… ou F1.x.y (fait), NV-… ou N2.x (point non vérifié), C… ou
« conséquence n » (point de conception de la note, résolu par les sources des
faits qui le fondent), § x.y (section de la note). Un renvoi à la note entière
(« R5 », « digest R6 », ou « le digest » quand le contexte nomme la note)
figure sous la forme « R5 (section 12.3) », où 12.3 est la section de CT-2 qui
le porte, avec les sources de la note qui concernent ce passage. Une plage
(« R2 F-A21 à F-A29 ») est résolue identifiant par identifiant ; les
identifiants NV-… sans préfixe de la table des backends (section 11.2)
relèvent de R3. La mention « aucune source primaire publique dans la note ;
fait non recoupable » signale un point que la note n'appuie sur aucune page
publique.

### C.1 R1 — Model Context Protocol

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R1 conséquence 2 | Corrélation des messages sans session MCP : `id` JSON-RPC, jeton de progression, requêtes MRTR (sources des faits qui fondent ce point) | https://modelcontextprotocol.io/specification/2026-07-28/changelog ; https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress ; https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr | 2026-10-22 |
| R1 Q1 | Révisions publiées du protocole ; révision courante 2026-07-28, sans état (`initialize` et `Mcp-Session-Id` supprimés) | https://modelcontextprotocol.io/specification/versioning ; https://modelcontextprotocol.io/specification/2025-03-26/changelog ; https://modelcontextprotocol.io/specification/2025-06-18/changelog ; https://modelcontextprotocol.io/specification/2025-11-25/changelog ; https://modelcontextprotocol.io/specification/2026-07-28/changelog ; https://modelcontextprotocol.io/specification/draft/changelog ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index ; https://modelcontextprotocol.io/specification/2026-07-28/deprecated ; https://modelcontextprotocol.io/community/feature-lifecycle | 2026-10-22 |
| R1 Q2 | Cycle de vie : ère moderne (version par requête dans `_meta`, `server/discover`) et ère héritée (`initialize`, `ping`), arrêt stdio | https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index ; https://modelcontextprotocol.io/specification/2026-07-28/server/discover ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts ; https://modelcontextprotocol.io/specification/2026-07-28/changelog ; https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio ; https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle ; https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ping | 2026-10-22 |
| R1 Q3 | Outils : `tools/list`, `tools/call`, objet `Tool`, noms, annotations non fiables, erreurs, `list_changed` | https://modelcontextprotocol.io/specification/2026-07-28/server/tools ; https://modelcontextprotocol.io/specification/2025-11-25/server/tools ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index | 2026-10-22 |
| R1 Q4 | Utilitaires : progression, annulation, journalisation, pagination, indications de cache, conventions `_meta` | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress ; https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation ; https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging ; https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/logging ; https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/completion ; https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination ; https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index ; https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts | 2026-10-22 |
| R1 Q5 | Requêtes du serveur vers le client : motif MRTR (`input_required`), sampling, elicitation, roots ; ère héritée | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr ; https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/index ; https://modelcontextprotocol.io/specification/2026-07-28/client/sampling ; https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation ; https://modelcontextprotocol.io/specification/2026-07-28/client/roots ; https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts | 2026-10-22 |
| R1 Q6 | Transport stdio : un message JSON-RPC par ligne, UTF-8, `stderr` réservé aux journaux | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio ; https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/index ; https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index | 2026-10-22 |
| R1 Q7 | Transport Streamable HTTP : POST unique, flux SSE de réponse, en-têtes `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, formes héritées | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http ; https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ; https://modelcontextprotocol.io/specification/2024-11-05/basic/transports | 2026-10-22 |
| R1 Q8 | Autorisation : OAuth 2.1, métadonnées de ressource protégée, indicateurs de ressource, interdiction du relais de jeton, consentement par client | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/index ; https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery ; https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration ; https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations ; https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices ; https://www.rfc-editor.org/rfc/rfc9728.html ; https://www.rfc-editor.org/rfc/rfc8707.html | 2026-10-22 |
| R1 Q9 | Extensions, contexte de trace W3C dans `_meta`, `subscriptions/listen`, `resultType`, politique des codes d'erreur | https://modelcontextprotocol.io/docs/extensions/overview ; https://modelcontextprotocol.io/extensions/tasks/overview ; https://modelcontextprotocol.io/extensions/apps/overview ; https://modelcontextprotocol.io/specification/2026-07-28/basic/index ; https://github.com/open-telemetry/semantic-conventions-genai ; https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/main/docs/gen-ai/mcp.md ; https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions ; https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts | 2026-10-22 |
| R1 Q11 | SDK officiels : niveaux, versions publiées et révisions du protocole prises en charge | https://modelcontextprotocol.io/docs/2026-07-28/sdk ; https://registry.npmjs.org/@modelcontextprotocol/sdk ; https://ts.sdk.modelcontextprotocol.io/v2/migration/upgrade-to-v2 ; https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions.md ; https://ts.sdk.modelcontextprotocol.io/v2/serving/legacy-clients.html ; https://pypi.org/pypi/mcp/json ; https://py.sdk.modelcontextprotocol.io/whats-new/ | 2026-10-22 |

### C.2 R2 — API des fournisseurs de modèles

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R2 F-A2 | API Messages : méthode et chemin `POST /v1/messages` | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A9 | API Messages : champ `system`, chaîne ou tableau de `TextBlockParam` | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A15 | API Messages : bloc `tool_use` de la réponse (`id`, `name`, `input`) | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A16 | API Messages : bloc `tool_result` (`tool_use_id`, `content`, `is_error`) | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A18 | API Messages : objet `Message` rendu (`id`, `content`, `stop_reason`, `usage`, …) | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A19 | API Messages : énumération `StopReason` (sept valeurs) | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A20 | API Messages : objet `Usage` (jetons d'entrée, de sortie et de cache) | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A21 | Flux SSE d'Anthropic : déroulement officiel, de `message_start` à `message_stop` | https://platform.claude.com/docs/en/build-with-claude/streaming | 2026-10-22 |
| R2 F-A22 | Flux SSE d'Anthropic : événements `ping` | https://platform.claude.com/docs/en/build-with-claude/streaming | 2026-10-22 |
| R2 F-A23 | Flux SSE d'Anthropic : événement `error` après un statut `200` | https://platform.claude.com/docs/en/build-with-claude/streaming ; https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 F-A24 | Flux SSE d'Anthropic : types d'événements inconnus à traiter sans erreur | https://platform.claude.com/docs/en/build-with-claude/streaming | 2026-10-22 |
| R2 F-A25 | Flux SSE d'Anthropic : types de delta (`text_delta`, `input_json_delta`, …) | https://platform.claude.com/docs/en/build-with-claude/streaming ; https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R2 F-A26 | Flux SSE d'Anthropic : règle officielle d'accumulation des deltas | https://platform.claude.com/docs/en/build-with-claude/streaming | 2026-10-22 |
| R2 F-A27 | Exemple officiel de flux avec outil : premier `partial_json` vide, `stop_reason` dans `message_delta` | https://platform.claude.com/docs/en/build-with-claude/streaming | 2026-10-22 |
| R2 F-A28 | Accumulation des événements par le SDK Python d'Anthropic (`accumulate_event`) | https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/lib/streaming/_messages.py | 2026-10-22 |
| R2 F-A29 | SDK TypeScript d'Anthropic : même accumulation, événement inconnu transmis tel quel | https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/helpers.md ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/lib/MessageStream.ts ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/helpers.md | 2026-10-22 |
| R2 F-A31 | Codes HTTP et types d'erreur de l'API ; taille de requête limitée à 32 Mo | https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 F-A32 | Forme du corps d'erreur (`type`, `error.type`, `error.message`, `request_id`) | https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 F-A33 | En-tête de réponse `request-id` | https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 F-A34 | Claude dans Amazon Bedrock : point `/anthropic/v1/messages`, corps de l'API directe, flux SSE standard | https://platform.claude.com/docs/en/build-with-claude/claude-in-amazon-bedrock | 2026-10-22 |
| R2 F-A35 | Intégration Bedrock héritée (`InvokeModel`) : différences avec l'API directe | https://platform.claude.com/docs/en/build-with-claude/claude-on-amazon-bedrock-legacy | 2026-10-22 |
| R2 F-A36 | Corps `InvokeModel` pour Claude : `anthropic_version: "bedrock-2023-05-31"` obligatoire | https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages-request-response.html ; https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages.html | 2026-10-22 |
| R2 F-A37 | URI `InvokeModel`, flux `InvokeModelWithResponseStream` et `PayloadPart` (`bytes` en base64) | https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html ; https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithResponseStream.html ; https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_PayloadPart.html | 2026-10-22 |
| R2 F-A38 | Claude sur Google Cloud : `model` dans l'URL, `anthropic_version` dans le corps | https://platform.claude.com/docs/en/build-with-claude/claude-on-vertex-ai | 2026-10-22 |
| R2 F-B1 | Bedrock `Converse` : chemin et champs de la requête | https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html | 2026-10-22 |
| R2 F-B2 | Bedrock `Converse` : blocs `ToolUseBlock` et `ToolResultBlock` | https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ToolUseBlock.html ; https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ToolResultBlock.html | 2026-10-22 |
| R2 F-E1 | Format SSE (WHATWG) : type `text/event-stream`, décodage UTF-8, marque d'ordre d'octets | https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream ; https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation | 2026-10-22 |
| R2 F-E2 | Format SSE : grammaire ABNF du flux d'événements | https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream | 2026-10-22 |
| R2 F-E3 | Format SSE : interprétation ligne par ligne (ligne vide, commentaire, champ) | https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation | 2026-10-22 |
| R2 F-E4 | Format SSE : champs `event`, `data`, `id`, `retry` | https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation | 2026-10-22 |
| R2 F-E5 | Format SSE : distribution d'un événement, type par défaut `message` | https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation | 2026-10-22 |
| R2 F-G1 | Gemini : points `generateContent` et `streamGenerateContent` | https://ai.google.dev/api/generate-content | 2026-10-22 |
| R2 F-G2 | Gemini : `alt=sse` présent seulement dans les exemples de la référence | https://ai.google.dev/api/generate-content | 2026-10-22 |
| R2 F-G3 | Gemini : clé d'API (`x-goog-api-key`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`) | https://ai.google.dev/gemini-api/docs/api-key | 2026-10-22 |
| R2 F-G4 | Gemini : réponse `GenerateContentResponse` (`candidates`, `usageMetadata`, `finishReason`) | https://ai.google.dev/api/generate-content | 2026-10-22 |
| R2 F-G5 | Gemini : `Part`, `functionCall`, `functionResponse` | https://ai.google.dev/api/generate-content | 2026-10-22 |
| R2 F-G6 | Gemini : configuration de l'appel de fonction (`FunctionCallingConfig`) | https://ai.google.dev/api/caching | 2026-10-22 |
| R2 F-G7 | Gemini : surface « Interactions » mise en avant par les guides | https://ai.google.dev/gemini-api/docs/text-generation ; https://ai.google.dev/gemini-api/docs/function-calling | 2026-10-22 |
| R2 F-O2 | Chat Completions : `POST /chat/completions`, Responses recommandée pour un nouveau projet | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O3 | API OpenAI : authentification `Bearer`, en-têtes de requête et de réponse | https://developers.openai.com/api/reference/overview | 2026-10-22 |
| R2 F-O4 | Chat Completions : `model`, `messages`, rôles `system` et `developer` | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O7 | Chat Completions : `stream` et `stream_options.include_usage` | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O8 | Chat Completions : message de rôle `tool` (`tool_call_id`, `content`) | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O9 | Chat Completions : objet `ChatCompletion` rendu, `usage` (`prompt_tokens`, `completion_tokens`) | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O10 | Chat Completions : `tool_calls[]` (`id`, `function.name`, `function.arguments` en chaîne JSON) | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O12 | Chat Completions en flux : objet `chat.completion.chunk`, `usage` au dernier chunk, `obfuscation` | https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events | 2026-10-22 |
| R2 F-O13 | Chat Completions : exemple officiel de flux, lignes `data:` et sentinelle `[DONE]` | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create | 2026-10-22 |
| R2 F-O14 | Accumulation des chunks par les fonctions d'aide du SDK Python d'OpenAI (`helpers.md`) | https://raw.githubusercontent.com/openai/openai-python/main/helpers.md | 2026-10-22 |
| R2 F-R1 | Responses : `POST /responses`, champs principaux (`instructions`, `input`, `previous_response_id`) | https://developers.openai.com/api/reference/resources/responses/methods/create | 2026-10-22 |
| R2 F-R2 | Responses : objet `Response` rendu, `usage` | https://developers.openai.com/api/reference/resources/responses/methods/create | 2026-10-22 |
| R2 F-R3 | Responses : item de sortie `function_call` (`call_id`, `name`, `arguments`) | https://developers.openai.com/api/reference/resources/responses/methods/create | 2026-10-22 |
| R2 F-R4 | Responses : item d'entrée `function_call_output` (`call_id`, `output`) | https://developers.openai.com/api/reference/resources/responses/methods/create ; https://developers.openai.com/api/reference/resources/responses | 2026-10-22 |
| R2 F-R5 | Responses en flux : événements SSE typés | https://developers.openai.com/api/reference/resources/responses/streaming-events | 2026-10-22 |
| R2 F-R6 | Responses en flux : définitions de `response.created`, `response.completed`, `response.failed`, `response.incomplete` | https://developers.openai.com/api/reference/resources/responses/streaming-events | 2026-10-22 |
| R2 F-R7 | Responses recommandée pour les nouveaux projets ; Chat Completions reste prise en charge | https://developers.openai.com/api/docs/guides/migrate-to-responses.md | 2026-10-22 |
| R2 F-R8 | Responses : stockage par défaut, `store: false`, contexte porté par `previous_response_id` | https://developers.openai.com/api/docs/guides/migrate-to-responses.md | 2026-10-22 |
| R2 F-R9 | Flux de Responses et de Chat Completions : nature différente et accumulation | https://developers.openai.com/api/docs/guides/migrate-to-responses.md ; https://developers.openai.com/api/docs/guides/function-calling.md ; https://developers.openai.com/api/docs/guides/streaming-responses.md | 2026-10-22 |
| R2 F-S1 | SDK Python d'Anthropic : lecture de `ANTHROPIC_BASE_URL` | https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_client.py ; https://platform.claude.com/docs/en/cli-sdks-libraries/sdks/python | 2026-10-22 |
| R2 F-S2 | SDK TypeScript d'Anthropic : lecture de `ANTHROPIC_BASE_URL` | https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/client.ts | 2026-10-22 |
| R2 F-S3 | SDK Python d'OpenAI : lecture de `OPENAI_BASE_URL` | https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_client.py ; https://raw.githubusercontent.com/openai/openai-python/main/README.md | 2026-10-22 |
| R2 F-S4 | SDK Node d'OpenAI : lecture de `OPENAI_BASE_URL`, désactivée par l'option `provider` | https://raw.githubusercontent.com/openai/openai-node/master/src/client.ts | 2026-10-22 |
| R2 F-S11 | Node.js : `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` lus seulement avec `NODE_USE_ENV_PROXY=1` ou `--use-env-proxy` | https://raw.githubusercontent.com/nodejs/node/main/doc/api/cli.md | 2026-10-22 |
| R2 F-Z1 | Azure OpenAI, API datée : chemin par déploiement, paramètre `api-version`, en-têtes `api-key` ou `Bearer` | https://learn.microsoft.com/en-us/azure/foundry/openai/reference | 2026-10-22 |
| R2 F-Z2 | Azure OpenAI, API v1 : chemin `/openai/v1/`, sans `api-version`, modèle nommé dans le corps | https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle | 2026-10-22 |
| R2 NV-4 | Contenu exact de `chunk.bytes` pour Claude dans `InvokeModelWithResponseStream` : non vérifié (pages lues) | https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_PayloadPart.html ; https://platform.claude.com/docs/en/build-with-claude/claude-on-amazon-bedrock-legacy | 2026-10-22 |
| R2 NV-5 | Encodage du flux de `streamRawPredict` sur Google Cloud : non vérifié (pages lues) | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/claude/use-claude ; https://platform.claude.com/docs/en/build-with-claude/claude-on-vertex-ai | 2026-10-22 |
| R2 NV-6 | Règle d'accumulation de Chat Completions écrite en prose par OpenAI : non trouvée (pages lues) | https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events ; https://raw.githubusercontent.com/openai/openai-python/main/helpers.md ; https://developers.openai.com/api/docs/guides/function-calling.md | 2026-10-22 |
| R2 NV-8 | Définition normative de `alt=sse` pour Gemini : non trouvée (pages lues) | https://ai.google.dev/api/generate-content ; https://ai.google.dev/gemini-api/docs/text-generation | 2026-10-22 |
| R2 NV-9 | Surface « Interactions » de Gemini : référence complète non lue (guides lus) | https://ai.google.dev/gemini-api/docs/text-generation ; https://ai.google.dev/gemini-api/docs/function-calling | 2026-10-22 |
| R2 NV-10 | Azure OpenAI, API datée : identité du corps avec Chat Completions non vérifiée (page lue) | https://learn.microsoft.com/en-us/azure/foundry/openai/reference | 2026-10-22 |
| R2 NV-11 | Forme du corps d'erreur HTTP d'OpenAI : non recherchée | aucune source primaire publique dans la note ; fait non recoupable | — |
| R2 NV-13 | Suite d'un flux SSE d'Anthropic après `event: error` : non documentée, non testée (pages lues) | https://platform.claude.com/docs/en/build-with-claude/streaming ; https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 (section 19.3) | Forme documentée de l'API Messages reproduite par le simulateur : chemin, en-têtes, réponse, flux, erreurs | https://platform.claude.com/docs/en/api/messages ; https://platform.claude.com/docs/en/api/overview ; https://platform.claude.com/docs/en/build-with-claude/streaming ; https://platform.claude.com/docs/en/api/errors | 2026-10-22 |
| R2 (section 20) | Lecture de `ANTHROPIC_BASE_URL` et `OPENAI_BASE_URL` dans le code des quatre SDK | https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_client.py ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/client.ts ; https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_client.py ; https://raw.githubusercontent.com/openai/openai-node/master/src/client.ts | 2026-10-22 |

### C.3 R3 — Clés de signature et modules de garde

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R3 F-2 | AWS KMS : la clé privée Ed25519 ne quitte jamais KMS en clair | https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html | 2026-10-22 |
| R3 F-3 | AWS KMS : `ED25519_SHA_512` (message brut) et `ED25519_PH_SHA_512` (double hachage) | https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html | 2026-10-22 |
| R3 F-5 | AWS KMS `Sign` : message de 4096 octets au plus | https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html | 2026-10-22 |
| R3 F-9 | AWS CloudHSM : mécanisme propriétaire `CKM_CLOUDHSM_EDDSA`, opérations en une seule partie | https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html | 2026-10-22 |
| R3 F-10 | AWS CloudHSM : Ed25519 seulement sur `hsm2m.medium` en mode non FIPS | https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html | 2026-10-22 |
| R3 F-11 | AWS CloudHSM : 16 000 octets au plus pour PureEdDSA | https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html | 2026-10-22 |
| R3 F-21 | Vault Transit : `exportable` faux par défaut et irréversible une fois posé | https://developer.hashicorp.com/vault/api-docs/secret/transit | 2026-10-22 |
| R3 F-24 | Vault Transit : type `ed25519` ; Ed25519 non certifié en mode FIPS 140-3 | https://developer.hashicorp.com/vault/docs/secrets/transit | 2026-10-22 |
| R3 F-26 | OpenBao Transit : export, dérivation et rotation, même sémantique que Vault | https://openbao.org/docs/api/secret/transit/ ; https://openbao.org/docs/secrets/transit/ | 2026-10-22 |
| R3 F-29 | YubiHSM 2 : capacités `sign-eddsa` et `exportable-under-wrap`, posées à la création | https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html | 2026-10-22 |
| R3 F-31 | Thales Luna : `CKM_EDDSA` approuvé FIPS à partir du micrologiciel 7.8.9 | https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm | 2026-10-22 |
| R3 F-34 | Entrust nShield : `CKM_EDDSA` en une seule partie, sans paramètre pour Ed25519 | https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html | 2026-10-22 |
| R3 F-51 | PKCS#11 3.1 : clé publique `CKK_EC_EDWARDS`, `CKA_EC_PARAMS` et `CKA_EC_POINT` en petit-boutiste | https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html | 2026-10-22 |
| R3 F-54 | PKCS#11 3.1 : mécanisme `CKM_EDDSA`, schéma Ed25519 sans paramètre | https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html | 2026-10-22 |
| R3 F-57 | PKCS#11 3.1 : signature EdDSA de 64 octets `R ‖ S` | https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html | 2026-10-22 |
| R3 F-58 | YubiHSM 2 : certificat X.509 d'attestation d'une clé générée dans le module | https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html ; https://docs.yubico.com/hardware/oid/oid-product-arc.html | 2026-10-22 |
| R3 F-59 | YubiHSM 2 : commande `SIGN ATTESTATION CERTIFICATE` | https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html | 2026-10-22 |
| R3 F-60 | Thales Luna : confirmation de clé publique `cmu getpkc`, clés non extractibles seulement | https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm | 2026-10-22 |
| R3 F-61 | Entrust nShield : attestation de clé (`nfkmattest`) | https://nshielddocs.entrust.com/key-attestation-docs/intro.html ; https://nshielddocs.entrust.com/app-notes/key-attestation-format/verification.html | 2026-10-22 |
| R3 F-62 | AWS KMS `Encrypt` : 4096 octets au plus | https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html | 2026-10-22 |
| R3 F-63 | AWS KMS : contexte de chiffrement non secret, visible dans CloudTrail | https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html | 2026-10-22 |
| R3 F-66 | Google Cloud KMS `encrypt` : 64 KiB au plus | https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt | 2026-10-22 |
| R3 F-68 | Azure Key Vault `wrapKey` : enveloppe d'une clé symétrique | https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 | 2026-10-22 |
| R3 F-70 | TPM 2.0 (`tpm2_create`) : scellement d'une donnée de 128 octets au plus | https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_create.1.md | 2026-10-22 |
| R3 F-71 | TPM 2.0 (`tpm2_unseal`) : descellement sous politique PCR | https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_unseal.1.md | 2026-10-22 |
| R3 F-72 | TPM 2.0 : politique PCR (`tpm2_createpolicy`, `tpm2_policypcr`) | https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_createpolicy.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_policypcr.1.md | 2026-10-22 |
| R3 F-74 | Azure Key Vault et Managed HSM : aucune opération d'export | https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details | 2026-10-22 |
| R3 F-75 | Vault et OpenBao : clé non exportable par défaut, choix irréversible | https://developer.hashicorp.com/vault/api-docs/secret/transit ; https://openbao.org/docs/api/secret/transit/ | 2026-10-22 |
| R3 F-76 | YubiHSM 2 : export seulement sous enveloppe, si la capacité a été posée à la création | https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html | 2026-10-22 |
| R3 F-78 | AWS KMS : administrateurs de clé sans droit d'usage cryptographique (politique par défaut) | https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html | 2026-10-22 |
| R3 F-79 | Google Cloud KMS : séparation des tâches entre gestion et usage des clés | https://docs.cloud.google.com/kms/docs/separation-of-duties | 2026-10-22 |
| R3 F-80 | Azure : rôles Crypto Officer et Crypto User (Key Vault, Managed HSM) | https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation | 2026-10-22 |
| R3 F-81 | AWS KMS : tous les appels journalisés par CloudTrail | https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html | 2026-10-22 |
| R3 F-82 | Vault : dispositifs d'audit, valeurs hachées par HMAC-SHA256 | https://developer.hashicorp.com/vault/docs/audit | 2026-10-22 |
| R3 F-83 | Google Cloud KMS : journaux d'audit (Admin Activity, Data Access) | https://docs.cloud.google.com/kms/docs/audit-logging | 2026-10-22 |
| R3 F-84 | Azure Key Vault : journalisation dans un compte de stockage | https://learn.microsoft.com/en-us/azure/key-vault/general/logging | 2026-10-22 |
| R3 F-85 | AWS KMS : rotation automatique annuelle des clés symétriques, aucune pour les clés asymétriques | https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html | 2026-10-22 |
| R3 F-86 | Google Cloud KMS : pas de rotation automatique des clés asymétriques | https://docs.cloud.google.com/kms/docs/key-rotation | 2026-10-22 |
| R3 F-87 | Azure Key Vault : rotation « at least every two years » | https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details | 2026-10-22 |
| R3 F-88 | Vault et OpenBao : rotation périodique recommandée, sans période chiffrée | https://developer.hashicorp.com/vault/docs/secrets/transit ; https://openbao.org/docs/secrets/transit/ | 2026-10-22 |
| R3 NV-1 | AWS CloudHSM : génération d'une paire Ed25519 non documentée (page lue) | https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html | 2026-10-22 |
| R3 NV-2 | Google Cloud KMS : statut de `EC_SIGN_ED25519`, borne de `data`, non-exportabilité, journaux Data Access : non vérifiés (pages lues) | https://docs.cloud.google.com/kms/docs/algorithms ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; https://docs.cloud.google.com/kms/docs/audit-logging | 2026-10-22 |
| R3 NV-3 | Thales Luna : version d'introduction de `CKM_EDDSA` et prise en charge Edwards par `cmu getpkc` : non vérifiées (pages lues) | https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm ; https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm | 2026-10-22 |
| R3 NV-4 | Entrust nShield : restrictions FIPS 140 niveau 3 et version d'introduction d'EdDSA : non vérifiées (page lue) | https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html | 2026-10-22 |
| R3 NV-5 | TPM 2.0 : prise en charge réelle d'EdDSA, documents TCG inaccessibles : non vérifié (sources lues) | https://www.rfc-editor.org/rfc/rfc9684.txt ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/common/alg.md | 2026-10-22 |
| R3 NV-6 | Utimaco : mécanisme PKCS#11, micrologiciel et statut FIPS pour Ed25519 : non vérifiés (page produit lue ; fiche technique servie derrière un formulaire) | https://utimaco.com/data-protection/gp-hsm/utrust-general-purpose-hsm | 2026-10-22 |
| R3 NV-7 | Nitrokey HSM 2 / SmartCard-HSM : absence d'Ed25519 sans document de 2026 qui la confirme (pages lues) | https://shop.nitrokey.com/shop/nitrokey-hsm-2-7 ; https://www.smartcard-hsm.com/features.html ; https://support.nitrokey.com/t/nitrokey-hsm2-support-for-ed25519/2484 | 2026-10-22 |
| R3 NV-8 | Android Keystore hors StrongBox : prise en charge d'Ed25519 non tranchée (pages lues) | https://developer.android.com/privacy-and-security/keystore ; https://developer.android.com/reference/android/security/keystore/KeyProperties ; https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec | 2026-10-22 |
| R3 NV-9 | YubiHSM 2 FIPS : Ed25519 en mode approuvé non vérifié (fiche technique lue) | https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf | 2026-10-22 |
| R3 NV-10 | Azure : page REST `unwrapKey` non lue (pages lues : `wrapKey`, journalisation) | https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 ; https://learn.microsoft.com/en-us/azure/key-vault/general/logging | 2026-10-22 |
| R3 NV-11 | AWS KMS : format binaire de la signature Ed25519 rendue par `Sign` non décrit (page lue) | https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html | 2026-10-22 |
| R3 NV-13 | SoftHSM2 : version du passage aux mécanismes standard `CKM_EDDSA` non écrite dans `NEWS` (fichiers lus) | https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/NEWS ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/pkcs11/pkcs11.h ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/SoftHSM.cpp | 2026-10-22 |
| R3 (section 11) | Origine des faits sur les produits de la section 11 : pages des fournisseurs, PKCS#11 3.0 et 3.1, RFC 9684, dépôts officiels | https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html ; https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html ; https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html ; https://www.rfc-editor.org/rfc/rfc9684.txt ; https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html ; https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html ; https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html ; https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html ; https://docs.cloud.google.com/kms/docs/algorithms ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; https://docs.cloud.google.com/kms/docs/key-rotation ; https://docs.cloud.google.com/kms/docs/audit-logging ; https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details ; https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 ; https://learn.microsoft.com/en-us/azure/key-vault/general/logging ; https://developer.hashicorp.com/vault/api-docs/secret/transit ; https://developer.hashicorp.com/vault/docs/secrets/transit ; https://developer.hashicorp.com/vault/docs/audit ; https://openbao.org/docs/api/secret/transit/ ; https://openbao.org/docs/secrets/transit/ ; https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html ; https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm ; https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm ; https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html ; https://nshielddocs.entrust.com/key-attestation-docs/intro.html ; https://utimaco.com/data-protection/gp-hsm/utrust-general-purpose-hsm ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/NEWS ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/pkcs11/pkcs11.h ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/common/alg.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_create.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_unseal.1.md ; https://shop.nitrokey.com/shop/nitrokey-hsm-2-7 ; https://www.smartcard-hsm.com/features.html ; https://support.nitrokey.com/t/nitrokey-hsm2-support-for-ed25519/2484 ; https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave ; https://developer.android.com/privacy-and-security/keystore ; https://docs.yubico.com/hardware/oid/oid-product-arc.html ; https://nshielddocs.entrust.com/app-notes/key-attestation-format/verification.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_createpolicy.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_policypcr.1.md ; https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html ; https://docs.cloud.google.com/kms/docs/separation-of-duties ; https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation ; https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html ; https://developer.android.com/reference/android/security/keystore/KeyProperties ; https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/SoftHSM.cpp | 2026-10-22 |
| R3 (section 11.2) | Table des backends, établie page par page | https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html ; https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html ; https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html ; https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html ; https://docs.cloud.google.com/kms/docs/algorithms ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; https://docs.cloud.google.com/kms/docs/key-rotation ; https://docs.cloud.google.com/kms/docs/audit-logging ; https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details ; https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 ; https://learn.microsoft.com/en-us/azure/key-vault/general/logging ; https://developer.hashicorp.com/vault/api-docs/secret/transit ; https://developer.hashicorp.com/vault/docs/secrets/transit ; https://developer.hashicorp.com/vault/docs/audit ; https://openbao.org/docs/api/secret/transit/ ; https://openbao.org/docs/secrets/transit/ ; https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html ; https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm ; https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm ; https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html ; https://nshielddocs.entrust.com/key-attestation-docs/intro.html ; https://utimaco.com/data-protection/gp-hsm/utrust-general-purpose-hsm ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/NEWS ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/pkcs11/pkcs11.h ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/common/alg.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_create.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_unseal.1.md ; https://www.rfc-editor.org/rfc/rfc9684.txt ; https://shop.nitrokey.com/shop/nitrokey-hsm-2-7 ; https://www.smartcard-hsm.com/features.html ; https://support.nitrokey.com/t/nitrokey-hsm2-support-for-ed25519/2484 ; https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave ; https://developer.android.com/privacy-and-security/keystore ; https://docs.yubico.com/hardware/oid/oid-product-arc.html ; https://nshielddocs.entrust.com/app-notes/key-attestation-format/verification.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html ; https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation ; https://developer.android.com/reference/android/security/keystore/KeyProperties ; https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/SoftHSM.cpp | 2026-10-22 |
| R3 (section 20) | HSM, KMS et TPM ne recouvrent pas la même chose pour Ed25519 (motif des classes de garde A à D) | https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html ; https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html ; https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html ; https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html ; https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html ; https://docs.cloud.google.com/kms/docs/algorithms ; https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; https://docs.cloud.google.com/kms/docs/key-rotation ; https://docs.cloud.google.com/kms/docs/audit-logging ; https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details ; https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details ; https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-7.4 ; https://learn.microsoft.com/en-us/azure/key-vault/general/logging ; https://developer.hashicorp.com/vault/api-docs/secret/transit ; https://developer.hashicorp.com/vault/docs/secrets/transit ; https://developer.hashicorp.com/vault/docs/audit ; https://openbao.org/docs/api/secret/transit/ ; https://openbao.org/docs/secrets/transit/ ; https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html ; https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html ; https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_EDDSA.htm ; https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/cmu/cmu_getpkc.htm ; https://nshielddocs.entrust.com/security-world-docs/v13.9.3/api-pkcs11/mechanisms.html ; https://nshielddocs.entrust.com/key-attestation-docs/intro.html ; https://utimaco.com/data-protection/gp-hsm/utrust-general-purpose-hsm ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/NEWS ; https://raw.githubusercontent.com/softhsm/SoftHSMv2/develop/src/lib/pkcs11/pkcs11.h ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/common/alg.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_create.1.md ; https://raw.githubusercontent.com/tpm2-software/tpm2-tools/master/man/tpm2_unseal.1.md ; https://www.rfc-editor.org/rfc/rfc9684.txt ; https://shop.nitrokey.com/shop/nitrokey-hsm-2-7 ; https://www.smartcard-hsm.com/features.html ; https://support.nitrokey.com/t/nitrokey-hsm2-support-for-ed25519/2484 ; https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave ; https://developer.android.com/privacy-and-security/keystore | 2026-10-22 |

### C.4 R4 — Sortie TLS, ICAP, passerelles et pare-feu

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R4 § 1.2 | Squid : `icap_service`, `adaptation_access`, `ssl_bump` | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre ; https://wiki.squid-cache.org/Features/ICAP ; https://wiki.squid-cache.org/Features/SslPeekAndSplice ; https://wiki.squid-cache.org/Features/DynamicSslCert | 2026-10-22 |
| R4 § 1.3 | Mandataires commerciaux : envoi du trafic déchiffré à un serveur ICAP tiers (Broadcom, Skyhigh, Fortinet, Check Point, F5) | https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-configuration/page-help-icap/respmod-reqmod.html ; https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-configuration/page-help-icap/page-help-icap-service.html ; https://knowledge.broadcom.com/external/article/368615/icap-isnt-sending-httpsssl-traffic.html ; https://success.skyhighsecurity.com/Skyhigh_Secure_Web_Gateway_(On-Prem)/Secure_Web_Gateway_Product_Guide/Proxies/ICAP_Server/About_ICAP_Servers ; https://success.skyhighsecurity.com/Skyhigh_Secure_Web_Gateway_(On-Prem)/Secure_Web_Gateway_Product_Guide/Data_Loss_Prevention/Preventing_Data_Loss_Using_an_ICAP_server/Prevent_Data_Loss_Using_an_ICAP_Server ; https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/952611/icap ; https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/170723/icap-configuration-example ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_in_Gateway_mode.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_Configuration_File.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_Data_Trickling_Parameters.htm ; https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-local-traffic-manager-implementations/configuring-content-adaptation-for-http-requests.html ; https://techdocs.f5.com/en-us/bigip-21-1-0/ssl-orchestrator-setup/topologies-in-sslo/services.html ; https://clouddocs.f5.com/ssl-orchestrator-config-converter/1.0/cm_sslo_how_to_configure_an_icap_service.html | 2026-10-22 |
| R4 C3.1 | Réponse SSE longue et ICAP : corps `chunked`, Preview, `204`, « trickling » (sources des faits qui fondent ce point) | https://www.rfc-editor.org/rfc/rfc3507 ; https://wiki.squid-cache.org/Features/ICAP ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_Data_Trickling_Parameters.htm ; https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/170723/icap-configuration-example | 2026-10-22 |
| R4 C3.4 | Miroir du trafic déchiffré : conditions de licence et juridiques de Palo Alto, Fortinet, Check Point (sources des faits qui fondent ce point) | https://docs.paloaltonetworks.com/network-security/decryption/administration/monitoring-decryption/configure-decryption-port-mirroring ; https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/decryption/decryption-concepts/decryption-mirroring ; https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/697110 ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_in_Gateway_mode.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityGateway_Guide/Content/Topics-FWG/Mirror-and-Decrypt.htm | 2026-10-22 |
| R4 C3.7 | Racine d'interception : magasin système, variables des piles HTTP, applications à épinglage (sources des faits qui fondent ce point) | https://docs.mitmproxy.org/stable/concepts/certificates/ ; https://wiki.squid-cache.org/Features/DynamicSslCert ; https://nodejs.org/api/cli.html ; https://www.python-httpx.org/environment_variables/ ; https://requests.readthedocs.io/en/latest/user/advanced/ ; https://pkg.go.dev/crypto/x509 ; https://docs.cloud.google.com/secure-web-proxy/docs/tls-inspection-overview | 2026-10-22 |
| R4 F1.1.4 | ICAP (RFC 3507) : corps encapsulés obligatoirement en `chunked` | https://www.rfc-editor.org/rfc/rfc3507 | 2026-10-22 |
| R4 F1.1.5 | ICAP : aperçu (Preview) et en-têtes de la réponse `OPTIONS` | https://www.rfc-editor.org/rfc/rfc3507 | 2026-10-22 |
| R4 F1.1.6 | ICAP : réponse `204` seulement si la requête porte `Allow: 204` | https://www.rfc-editor.org/rfc/rfc3507 | 2026-10-22 |
| R4 F1.1.9 | ICAP : aucune règle pour un corps de longueur inconnue ou sans fin | https://www.rfc-editor.org/rfc/rfc3507 | 2026-10-22 |
| R4 F1.2.1 | Squid : syntaxe et options de `icap_service` | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre | 2026-10-22 |
| R4 F1.2.2 | Squid : `adaptation_access`, une adaptation par point de vectorisation | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre | 2026-10-22 |
| R4 F1.2.4 | Squid : pas de `204` au-delà de 64 Ko ni pour une taille indéterminable | https://wiki.squid-cache.org/Features/ICAP | 2026-10-22 |
| R4 F1.2.6 | Squid : options `ssl-bump` de `http_port` | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre | 2026-10-22 |
| R4 F1.3.2 | Broadcom ProxySG / Edge SWG : service ICAP vers un serveur tiers | https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-configuration/page-help-icap/page-help-icap-service.html | 2026-10-22 |
| R4 F1.3.3 | Broadcom ProxySG : interception SSL préalable à l'envoi ICAP | https://knowledge.broadcom.com/external/article/368615/icap-isnt-sending-httpsssl-traffic.html | 2026-10-22 |
| R4 F1.3.6 | FortiGate : ICAP en mode mandataire, inspection HTTPS requise | https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/952611/icap | 2026-10-22 |
| R4 F1.3.9 | Check Point : client ICAP, inspection HTTPS requise | https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_in_Gateway_mode.htm | 2026-10-22 |
| R4 F1.3.11 | Check Point : « trickling » des réponses longues, dépendant de `Content-Length` | https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_Data_Trickling_Parameters.htm | 2026-10-22 |
| R4 F1.4.1 | Palo Alto Networks : miroir du trafic déchiffré (licence gratuite, mise en garde juridique) | https://docs.paloaltonetworks.com/network-security/decryption/administration/monitoring-decryption/configure-decryption-port-mirroring | 2026-10-22 |
| R4 F1.4.6 | FortiGate : miroir du trafic SSL dans les politiques, accord affiché à l'activation | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/697110 | 2026-10-22 |
| R4 F1.4.7 | Check Point : « Mirror and Decrypt », modes et prérequis | https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityGateway_Guide/Content/Topics-FWG/Mirror-and-Decrypt.htm | 2026-10-22 |
| R4 F1.5.11 | SDK TypeScript d'Anthropic : `fetch` global, mandataire par `fetchOptions`, Node 20 accepté | https://platform.claude.com/docs/en/api/sdks/typescript | 2026-10-22 |
| R4 F1.6.1 | LiteLLM : URL de base et clé côté hôte | https://docs.litellm.ai/docs/proxy/user_keys ; https://docs.litellm.ai/docs/anthropic_unified | 2026-10-22 |
| R4 F1.6.2 | LiteLLM : clés virtuelles | https://docs.litellm.ai/docs/proxy/virtual_keys | 2026-10-22 |
| R4 F1.6.3 | LiteLLM : journalisation, aucune intégrité revendiquée | https://docs.litellm.ai/docs/proxy/logging | 2026-10-22 |
| R4 F1.6.4 | LiteLLM : flux SSE, délais, keepalive, erreurs en cours de flux | https://docs.litellm.ai/docs/proxy/timeout | 2026-10-22 |
| R4 F1.6.5 | Portkey : configuration de l'hôte | https://portkey.ai/docs/integrations/llms/anthropic ; https://portkey.ai/docs/product/ai-gateway/virtual-keys | 2026-10-22 |
| R4 F1.6.6 | Portkey : journaux | https://portkey.ai/docs/product/observability/logs | 2026-10-22 |
| R4 F1.6.7 | Helicone : modes mandataire et asynchrone, URL de base, flux | https://docs.helicone.ai/references/proxy-vs-async ; https://docs.helicone.ai/integrations/anthropic/javascript ; https://docs.helicone.ai/getting-started/integration-method/gateway ; https://docs.helicone.ai/gateway/overview ; https://docs.helicone.ai/features/streaming | 2026-10-22 |
| R4 F1.6.8 | Cloudflare AI Gateway : URL de base et SDK | https://developers.cloudflare.com/ai-gateway/usage/providers/anthropic/ | 2026-10-22 |
| R4 F1.6.11 | Kong : greffon `ai-proxy`, principe et configuration | https://developer.konghq.com/plugins/ai-proxy/ ; https://developer.konghq.com/plugins/ai-proxy/reference/ | 2026-10-22 |
| R4 F1.6.13 | Azure API Management, fonctions de passerelle pour les API de modèles : périmètre et configuration | https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities | 2026-10-22 |
| R4 F1.7.1 | Anthropic : plages d'adresses IP publiées | https://platform.claude.com/docs/en/api/ip-addresses | 2026-10-22 |
| R4 F1.7.2 | OpenAI : plages de sortie publiées, aucune plage d'entrée sur les pages lues | https://developers.openai.com/api/docs/guides/ip-addresses ; https://developers.openai.com/api/docs/guides/ip-allowlist | 2026-10-22 |
| R4 F1.7.3 | Palo Alto Networks : objets adresse FQDN, résolus par DNS | https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/addresses/address-objects-fields ; https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/use-address-object-to-represent-ip-addresses/address-objects | 2026-10-22 |
| R4 F1.7.4 | FortiGate : adresses FQDN, résolues par DNS | https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/707266/fqdn-addresses | 2026-10-22 |
| R4 F1.7.5 | AWS Network Firewall : listes de domaines appliquées sur le SNI ou l'en-tête `Host` | https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-groups-domain-names.html | 2026-10-22 |
| R4 F1.7.6 | Azure Firewall : FQDN par DNS (règles réseau) et par SNI (règles d'application) | https://learn.microsoft.com/en-us/azure/firewall/fqdn-filtering-network-rules ; https://learn.microsoft.com/en-us/azure/firewall/features | 2026-10-22 |
| R4 F1.8.4 | Node.js : prise en charge native de `HTTPS_PROXY` conditionnelle (`NODE_USE_ENV_PROXY`, `--use-env-proxy`) | https://nodejs.org/api/cli.html ; https://nodejs.org/api/http.html | 2026-10-22 |
| R4 F1.8.5 | undici : `EnvHttpProxyAgent` à enregistrer explicitement | https://github.com/nodejs/undici/blob/main/docs/docs/api/EnvHttpProxyAgent.md | 2026-10-22 |
| R4 N2.10 | OpenAI : plages IP d'entrée de `api.openai.com` non publiées sur les pages lues (non vérifié) | https://developers.openai.com/api/docs/guides/ip-addresses ; https://developers.openai.com/api/docs/guides/ip-allowlist | 2026-10-22 |
| R4 (section 5.1.2) | En-tête d'origine encapsulé en RESPMOD après adaptation REQMOD : non documenté pour Squid, ProxySG, FortiGate, Check Point (pages lues) | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre ; https://wiki.squid-cache.org/Features/ICAP ; https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-configuration/page-help-icap/respmod-reqmod.html ; https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-configuration/page-help-icap/page-help-icap-service.html ; https://knowledge.broadcom.com/external/article/368615/icap-isnt-sending-httpsssl-traffic.html ; https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/952611/icap ; https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/170723/icap-configuration-example ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_in_Gateway_mode.htm ; https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_ThreatPrevention_AdminGuide/Content/Topics-TPG/ICAP_Client_Configuration_File.htm | 2026-10-22 |
| R4 (section 19.6) | Configuration ICAP de Squid lue dans le code source | https://raw.githubusercontent.com/squid-cache/squid/master/src/cf.data.pre | 2026-10-22 |

### C.5 R5 — Stockage WORM, journal en ajout seul, bail et conservation

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R5 § 1.1 | Amazon S3 Object Lock : modes Governance et Compliance, rétention, conservation légale, versions | https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html | 2026-10-22 |
| R5 § 1.2 | Amazon S3 : écritures conditionnelles `If-None-Match` et `If-Match` (`412`, `409`), ETag | https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html ; https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html | 2026-10-22 |
| R5 § 1.3 | Azure Blob : stockage immuable (niveau version et niveau conteneur) | https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview ; https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies ; https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-container-level-worm-policies | 2026-10-22 |
| R5 § 1.4 | Google Cloud Storage : Bucket Lock, rétention, Object Retention Lock, conservations | https://docs.cloud.google.com/storage/docs/bucket-lock ; https://docs.cloud.google.com/storage/docs/object-lock ; https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/insert ; https://docs.cloud.google.com/storage/docs/object-holds | 2026-10-22 |
| R5 § 1.5 | Hébergeurs suisses : verrouillage d'objets (Exoscale, cloudscale.ch, Infomaniak) | https://community.exoscale.com/product/storage/object-storage/how-to/versioning/index.md ; https://www.cloudscale.ch/en/knowledge-base/object-lock-for-immutable-objects ; https://www.infomaniak.com/en/support/faq/2763/manage-swiss-backup-acronis-immutable-storage | 2026-10-22 |
| R5 § 1.6 | Linux : attribut append-only, `O_APPEND`, `write`, `fsync` et `fdatasync` | https://man7.org/linux/man-pages/man1/chattr.1.html ; https://man7.org/linux/man-pages/man7/capabilities.7.html ; https://man7.org/linux/man-pages/man2/open.2.html ; https://man7.org/linux/man-pages/man2/write.2.html ; https://man7.org/linux/man-pages/man2/fsync.2.html ; https://www.postgresql.org/docs/current/wal-reliability.html | 2026-10-22 |
| R5 § 1.7 | Formats de journaux d'écriture anticipée (SQLite, LevelDB, PostgreSQL, iSCSI) : trames, sommes de contrôle, fin valide | https://www.sqlite.org/fileformat2.html#walformat ; https://github.com/google/leveldb/blob/main/doc/log_format.md ; https://www.postgresql.org/docs/current/wal-reliability.html ; https://www.postgresql.org/docs/current/wal-internals.html ; https://github.com/postgres/postgres/blob/master/src/include/access/xlogrecord.h ; https://www.rfc-editor.org/rfc/rfc3720.txt | 2026-10-22 |
| R5 § 1.8 | Bail et écrivain unique : jeton de clôture, Redlock, etcd, ZooKeeper, Consul, PostgreSQL, verrous de fichiers et NFS | https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html ; https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/ ; http://antirez.com/news/101 ; https://etcd.io/docs/v3.5/learning/api/ ; https://zookeeper.apache.org/doc/current/recipes.html ; https://zookeeper.apache.org/doc/current/zookeeperProgrammers.html ; https://developer.hashicorp.com/consul/docs/automate/session ; https://developer.hashicorp.com/consul/api-docs/kv ; https://www.postgresql.org/docs/current/explicit-locking.html ; https://www.postgresql.org/docs/current/functions-admin.html ; https://www.postgresql.org/docs/current/transaction-iso.html ; https://www.postgresql.org/docs/current/functions-datetime.html ; https://man7.org/linux/man-pages/man2/flock.2.html ; https://man7.org/linux/man-pages/man2/fcntl.2.html ; https://man7.org/linux/man-pages/man5/nfs.5.html | 2026-10-22 |
| R5 § 1.9 | Droit suisse : Olico art. 9 et 10, CO art. 958f (conservation, supports, contrôles) | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2002/216/20130101/fr/pdf-a/fedlex-data-admin-ch-eli-cc-2002-216-20130101-fr-pdf-a.pdf ; https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/27/317_321_377/20261001/fr/pdf-a/fedlex-data-admin-ch-eli-cc-27-317_321_377-20261001-fr-pdf-a.pdf | 2026-10-22 |
| R5 § 2 | Points non vérifiés : modes et bornes du verrouillage chez Exoscale et cloudscale.ch, aucun verrouillage documenté chez Swisscom ni en S3 chez Infomaniak (pages lues, qui ne tranchent pas ces points) | https://community.exoscale.com/product/storage/object-storage/how-to/versioning/index.md ; https://www.cloudscale.ch/en/knowledge-base/object-lock-for-immutable-objects ; https://www.infomaniak.com/en/support/faq/2763/manage-swiss-backup-acronis-immutable-storage ; Swisscom : aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R5 (section 12) | Origine des faits de la section 12 : appels système, journaux d'écriture anticipée, stockage WORM, conservation suisse | https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html ; https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html ; https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html ; https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview ; https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies ; https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-container-level-worm-policies ; https://docs.cloud.google.com/storage/docs/bucket-lock ; https://docs.cloud.google.com/storage/docs/object-lock ; https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/insert ; https://docs.cloud.google.com/storage/docs/object-holds ; https://community.exoscale.com/product/storage/object-storage/how-to/versioning/index.md ; https://www.cloudscale.ch/en/knowledge-base/object-lock-for-immutable-objects ; https://www.infomaniak.com/en/support/faq/2763/manage-swiss-backup-acronis-immutable-storage ; https://man7.org/linux/man-pages/man1/chattr.1.html ; https://man7.org/linux/man-pages/man7/capabilities.7.html ; https://man7.org/linux/man-pages/man2/open.2.html ; https://man7.org/linux/man-pages/man2/write.2.html ; https://man7.org/linux/man-pages/man2/fsync.2.html ; https://www.postgresql.org/docs/current/wal-reliability.html ; https://www.sqlite.org/fileformat2.html#walformat ; https://github.com/google/leveldb/blob/main/doc/log_format.md ; https://www.postgresql.org/docs/current/wal-internals.html ; https://github.com/postgres/postgres/blob/master/src/include/access/xlogrecord.h ; https://www.rfc-editor.org/rfc/rfc3720.txt ; https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2002/216/20130101/fr/pdf-a/fedlex-data-admin-ch-eli-cc-2002-216-20130101-fr-pdf-a.pdf ; https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/27/317_321_377/20261001/fr/pdf-a/fedlex-data-admin-ch-eli-cc-27-317_321_377-20261001-fr-pdf-a.pdf | 2026-10-22 |
| R5 (section 12.3) | `O_APPEND` atomique, écritures courtes, `write` sans durabilité, `fsync` du répertoire, erreurs d'écriture différée, caches d'écriture volatils | https://man7.org/linux/man-pages/man2/open.2.html ; https://man7.org/linux/man-pages/man2/write.2.html ; https://man7.org/linux/man-pages/man2/fsync.2.html ; https://www.postgresql.org/docs/current/wal-reliability.html | 2026-10-22 |
| R5 (section 12.6) | Attributs `a` et `i` de `chattr` : pose réservée à `CAP_LINUX_IMMUTABLE`, descripteurs déjà ouverts non affectés | https://man7.org/linux/man-pages/man1/chattr.1.html ; https://man7.org/linux/man-pages/man7/capabilities.7.html | 2026-10-22 |
| R5 (section 12.7) | Conservation dix ans dès la fin de l'exercice (CO art. 958f) ; supports modifiables au sens de l'Olico art. 9 al. 2 | https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/27/317_321_377/20261001/fr/pdf-a/fedlex-data-admin-ch-eli-cc-27-317_321_377-20261001-fr-pdf-a.pdf ; https://fedlex.data.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2002/216/20130101/fr/pdf-a/fedlex-data-admin-ch-eli-cc-2002-216-20130101-fr-pdf-a.pdf | 2026-10-22 |
| R5 (section 13.1) | Redis recommande des jetons de clôture pour tout verrou distribué | https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/ | 2026-10-22 |
| R5 (section 13.2) | Magasins de bail retenus (fichier, PostgreSQL, etcd) ; exclusion de Redis et Redlock | https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html ; https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/ ; https://etcd.io/docs/v3.5/learning/api/ ; https://www.postgresql.org/docs/current/transaction-iso.html ; https://www.postgresql.org/docs/current/functions-datetime.html ; https://man7.org/linux/man-pages/man2/flock.2.html | 2026-10-22 |
| R5 (section 13.3) | Jeton de clôture vérifié par le stockage : refus d'une écriture d'époque inférieure | https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html | 2026-10-22 |

### C.6 R6 — Rédaction des données sensibles

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R6 § 1.1 | Outils de référence : Presidio, Google Cloud Sensitive Data Protection, Amazon Comprehend | https://presidio.dataprivacystack.org/ ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md ; https://presidio.dataprivacystack.org/supported_entities/ ; https://presidio.dataprivacystack.org/anonymizer/ ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/anonymizer/index.md ; https://presidio.dataprivacystack.org/evaluation/ ; https://docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference ; https://docs.cloud.google.com/sensitive-data-protection/docs/transformations-reference ; https://docs.cloud.google.com/sensitive-data-protection/docs/likelihood ; https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html ; https://docs.aws.amazon.com/comprehend/latest/APIReference/API_RedactionConfig.html | 2026-10-22 |
| R6 § 1.2 | Formats des identifiants : IBAN et MOD 97-10, numéro AVS, cartes de paiement, E.164, adresses électroniques, NIR, Steuer-ID, codice fiscale | https://www.six-group.com/en/products-services/banking-services/payment-standardization/standards/iban.html ; https://www.bundesbank.de/en/tasks/payment-systems/services/iban-rules/iban-rules-626476 ; https://www.cfonb.org/fichiers/20140124103020_8_4_RIB_Le_nouveau_Releve_d_Identite_Bancaire_2001_03.pdf ; https://economiapertutti.bancaditalia.it/aree-tematiche/pagamenti/iban/index.html ; https://www.oesterreich.gv.at/de/themen/steuern_und_finanzen/bankgeschaefte/1/1/Seite.750210 ; https://clientebancario.bde.es/pcb/es/blog/que-se-esconde-tras-los-numeros-de-tu-cuenta-corriente-.html ; https://www.betaalvereniging.nl/en/knowledge-base/iban-and-bic/dutch-iban/ ; https://febelfin.be/en/themes/digitalization-innovation/overschrijvingen/a-traditional-bank-transfer ; https://www.wearepay.uk/wp-content/uploads/2018/10/Pay.UK-Standard-Format-of-the-IBAN-issued-in-the-UK-October18-1.pdf ; https://www.abbl.lu/luxembourg-register-of-iban-bic-codes/ ; https://www.tcmb.gov.tr/wps/wcm/connect/EN/TCMB+EN/Bottom+Menu/IBAN/Communique ; https://www.mnb.hu/letoltes/iban-ellenorzoszam-hu.pdf ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/63/1185_1183_1185/20240101/fr/html/fedlex-data-admin-ch-eli-cc-63-1185_1183_1185-20240101-fr-html-4.html ; https://www.newsd.admin.ch/newsd/message/attachments/10042.pdf ; https://www.bag.admin.ch/dam/fr/sd-web/mySwNKJa48F3/das-system-versichertenkarte-vom-01.04.2008 ; https://www.bsv.admin.ch/fr/numero-avs ; https://sozialversicherungen.admin.ch/fr/d/6692/download ; https://patents.google.com/patent/US2950048A/en ; https://americanexpress.com/content/dam/amex/uk/staticassets/merchant/pdf/support-and-services/American_Express_Getting_Started_Guide.pdf ; https://www.americanexpress.com/content/dam/amex/hk/en/merchant/pdf/HK_Merchant_Welcome_Pack_EN_0818.pdf ; https://www.itu.int/rec/T-REC-E.164-202602-I/en ; https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-E.164-202602-I!!PDF-E&type=items ; https://www.rfc-editor.org/rfc/rfc5322.txt ; https://www.rfc-editor.org/rfc/rfc5321.txt ; https://www.insee.fr/fr/metadonnees/definition/c1409 ; https://www.insee.fr/fr/information/6665188 ; https://www.bzst.de/DE/Privatpersonen/SteuerlicheIdentifikationsnummer/steuerlicheidentifikationsnummer_node.html ; https://www.agenziaentrate.gov.it/portale/documents/20143/2736730/Il+codice+fiscale_+versione+short.pdf/5bfc774e-5a28-1f2f-0b9a-b9193c988f05 ; https://www.agenziaentrate.gov.it/portale/documents/20143/233505/BrochureCF_Cittadini.pdf/a92a77e5-0427-ef5f-541a-3f07cdceb2a5 ; https://www.agenziaentrate.gov.it/portale/documents/20143/318757/Audizione+del+Direttore+dell+Agenzia+delle+Entrate+10+02+2016_Audizione+-+Codice+Fiscale+e+Omocodie+-+10+feb+2016+df.pdf/202e5395-f622-62e5-219a-7ce894d538a4 | 2026-10-22 |
| R6 § 1.3 | Adressage dans un document JSON : JSON Pointer (RFC 6901) et JSONPath (RFC 9535) | https://www.rfc-editor.org/rfc/rfc6901.txt ; https://www.rfc-editor.org/rfc/rfc9535.txt | 2026-10-22 |
| R6 § 1.4 | Textes de droit : RGPD, LPD révisée et message du Conseil fédéral, PFPDT, lignes directrices du CEPD | https://publications.europa.eu/resource/celex/32016R0679 ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/fr/html/fedlex-data-admin-ch-eli-cc-2022-491-20230901-fr-html-4.html ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/fga/2017/2057/fr/pdf-a/fedlex-data-admin-ch-eli-fga-2017-2057-fr-pdf-a.pdf ; https://www.edoeb.admin.ch/dam/fr/sd-web/5YmOO6MycdFN/annexe_des_directivesde2014.pdf ; https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en ; https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf ; https://www.edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en ; https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202602_anonymisation_v1_en_0.pdf | 2026-10-22 |
| R6 § 1.5 | Pièges : normalisation Unicode (UAX #15), confusables (UTS #39), données encodées (RFC 4648, RFC 3986) | https://www.unicode.org/reports/tr15/ ; https://www.unicode.org/reports/tr39/ ; https://www.rfc-editor.org/rfc/rfc4648.txt ; https://www.rfc-editor.org/rfc/rfc3986.txt | 2026-10-22 |
| R6 § 2 | Points non vérifiés : textes ISO 13616-1, ISO/IEC 7064 et ISO/IEC 7812 et registre IBAN de SWIFT inaccessibles, clés de contrôle AVS (EAN-13), NIR, Steuer-ID, codice fiscale, préfixes Visa et Mastercard (pages lues, qui ne tranchent pas ces points) | https://www.six-group.com/en/products-services/banking-services/payment-standardization/standards/iban.html ; https://febelfin.be/en/themes/digitalization-innovation/overschrijvingen/a-traditional-bank-transfer ; https://clientebancario.bde.es/pcb/es/blog/que-se-esconde-tras-los-numeros-de-tu-cuenta-corriente-.html ; https://www.mnb.hu/letoltes/iban-ellenorzoszam-hu.pdf ; https://www.wearepay.uk/wp-content/uploads/2018/10/Pay.UK-Standard-Format-of-the-IBAN-issued-in-the-UK-October18-1.pdf ; https://www.tcmb.gov.tr/wps/wcm/connect/EN/TCMB+EN/Bottom+Menu/IBAN/Communique ; https://www.bundesbank.de/en/tasks/payment-systems/services/iban-rules/iban-rules-626476 ; https://www.cfonb.org/fichiers/20140124103020_8_4_RIB_Le_nouveau_Releve_d_Identite_Bancaire_2001_03.pdf ; https://economiapertutti.bancaditalia.it/aree-tematiche/pagamenti/iban/index.html ; https://www.oesterreich.gv.at/de/themen/steuern_und_finanzen/bankgeschaefte/1/1/Seite.750210 ; https://www.betaalvereniging.nl/en/knowledge-base/iban-and-bic/dutch-iban/ ; https://www.abbl.lu/luxembourg-register-of-iban-bic-codes/ ; https://www.newsd.admin.ch/newsd/message/attachments/10042.pdf ; https://www.bag.admin.ch/dam/fr/sd-web/mySwNKJa48F3/das-system-versichertenkarte-vom-01.04.2008 ; https://www.insee.fr/fr/metadonnees/definition/c1409 ; https://www.insee.fr/fr/information/6665188 ; https://www.bzst.de/DE/Privatpersonen/SteuerlicheIdentifikationsnummer/steuerlicheidentifikationsnummer_node.html ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md ; https://www.agenziaentrate.gov.it/portale/documents/20143/2736730/Il+codice+fiscale_+versione+short.pdf/5bfc774e-5a28-1f2f-0b9a-b9193c988f05 ; https://www.agenziaentrate.gov.it/portale/documents/20143/233505/BrochureCF_Cittadini.pdf/a92a77e5-0427-ef5f-541a-3f07cdceb2a5 ; https://www.agenziaentrate.gov.it/portale/documents/20143/318757/Audizione+del+Direttore+dell+Agenzia+delle+Entrate+10+02+2016_Audizione+-+Codice+Fiscale+e+Omocodie+-+10+feb+2016+df.pdf/202e5395-f622-62e5-219a-7ce894d538a4 ; https://docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference ; https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html ; textes ISO, registre IBAN de SWIFT, préfixes Visa et Mastercard : aucune source primaire publique dans la note ; fait non recoupable | 2026-10-22 |
| R6 (section 10) | Origine des faits de la section 10 : outils de référence, formats des identifiants, RFC 6901, textes de droit | https://presidio.dataprivacystack.org/ ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md ; https://presidio.dataprivacystack.org/supported_entities/ ; https://presidio.dataprivacystack.org/anonymizer/ ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/anonymizer/index.md ; https://presidio.dataprivacystack.org/evaluation/ ; https://docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference ; https://docs.cloud.google.com/sensitive-data-protection/docs/transformations-reference ; https://docs.cloud.google.com/sensitive-data-protection/docs/likelihood ; https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html ; https://docs.aws.amazon.com/comprehend/latest/APIReference/API_RedactionConfig.html ; https://www.six-group.com/en/products-services/banking-services/payment-standardization/standards/iban.html ; https://www.bundesbank.de/en/tasks/payment-systems/services/iban-rules/iban-rules-626476 ; https://www.cfonb.org/fichiers/20140124103020_8_4_RIB_Le_nouveau_Releve_d_Identite_Bancaire_2001_03.pdf ; https://economiapertutti.bancaditalia.it/aree-tematiche/pagamenti/iban/index.html ; https://www.oesterreich.gv.at/de/themen/steuern_und_finanzen/bankgeschaefte/1/1/Seite.750210 ; https://clientebancario.bde.es/pcb/es/blog/que-se-esconde-tras-los-numeros-de-tu-cuenta-corriente-.html ; https://www.betaalvereniging.nl/en/knowledge-base/iban-and-bic/dutch-iban/ ; https://febelfin.be/en/themes/digitalization-innovation/overschrijvingen/a-traditional-bank-transfer ; https://www.wearepay.uk/wp-content/uploads/2018/10/Pay.UK-Standard-Format-of-the-IBAN-issued-in-the-UK-October18-1.pdf ; https://www.abbl.lu/luxembourg-register-of-iban-bic-codes/ ; https://www.tcmb.gov.tr/wps/wcm/connect/EN/TCMB+EN/Bottom+Menu/IBAN/Communique ; https://www.mnb.hu/letoltes/iban-ellenorzoszam-hu.pdf ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/63/1185_1183_1185/20240101/fr/html/fedlex-data-admin-ch-eli-cc-63-1185_1183_1185-20240101-fr-html-4.html ; https://www.newsd.admin.ch/newsd/message/attachments/10042.pdf ; https://www.bag.admin.ch/dam/fr/sd-web/mySwNKJa48F3/das-system-versichertenkarte-vom-01.04.2008 ; https://www.bsv.admin.ch/fr/numero-avs ; https://sozialversicherungen.admin.ch/fr/d/6692/download ; https://patents.google.com/patent/US2950048A/en ; https://americanexpress.com/content/dam/amex/uk/staticassets/merchant/pdf/support-and-services/American_Express_Getting_Started_Guide.pdf ; https://www.americanexpress.com/content/dam/amex/hk/en/merchant/pdf/HK_Merchant_Welcome_Pack_EN_0818.pdf ; https://www.itu.int/rec/T-REC-E.164-202602-I/en ; https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-E.164-202602-I!!PDF-E&type=items ; https://www.rfc-editor.org/rfc/rfc5322.txt ; https://www.rfc-editor.org/rfc/rfc5321.txt ; https://www.insee.fr/fr/metadonnees/definition/c1409 ; https://www.insee.fr/fr/information/6665188 ; https://www.bzst.de/DE/Privatpersonen/SteuerlicheIdentifikationsnummer/steuerlicheidentifikationsnummer_node.html ; https://www.agenziaentrate.gov.it/portale/documents/20143/2736730/Il+codice+fiscale_+versione+short.pdf/5bfc774e-5a28-1f2f-0b9a-b9193c988f05 ; https://www.agenziaentrate.gov.it/portale/documents/20143/233505/BrochureCF_Cittadini.pdf/a92a77e5-0427-ef5f-541a-3f07cdceb2a5 ; https://www.agenziaentrate.gov.it/portale/documents/20143/318757/Audizione+del+Direttore+dell+Agenzia+delle+Entrate+10+02+2016_Audizione+-+Codice+Fiscale+e+Omocodie+-+10+feb+2016+df.pdf/202e5395-f622-62e5-219a-7ce894d538a4 ; https://www.rfc-editor.org/rfc/rfc6901.txt ; https://publications.europa.eu/resource/celex/32016R0679 ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/fr/html/fedlex-data-admin-ch-eli-cc-2022-491-20230901-fr-html-4.html ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/fga/2017/2057/fr/pdf-a/fedlex-data-admin-ch-eli-fga-2017-2057-fr-pdf-a.pdf ; https://www.edoeb.admin.ch/dam/fr/sd-web/5YmOO6MycdFN/annexe_des_directivesde2014.pdf ; https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en ; https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf ; https://www.edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en ; https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202602_anonymisation_v1_en_0.pdf | 2026-10-22 |
| R6 (section 10.1) | Hachage sans secret réversible par dictionnaire (CEPD 01/2025, § 88 à 90, note 23) ; sel aléatoire de l'opérateur `hash` de Presidio depuis 2.2.361 | https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf ; https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/anonymizer/index.md | 2026-10-22 |
| R6 (section 10.2.1) | Évaluation d'un pointeur JSON (RFC 6901 § 4) : `~1` avant `~0`, noms comparés octet par octet | https://www.rfc-editor.org/rfc/rfc6901.txt | 2026-10-22 |
| R6 (section 10.3.1) | Formes de compatibilité NFKC (UAX #15) ; somme de contrôle chez Presidio et vraisemblance `POSSIBLE` chez Google | https://www.unicode.org/reports/tr15/ ; https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md ; https://docs.cloud.google.com/sensitive-data-protection/docs/likelihood | 2026-10-22 |
| R6 (section 10.3.2) | Longueur de l'IBAN par pays (sources nationales de la table) | https://www.six-group.com/en/products-services/banking-services/payment-standardization/standards/iban.html ; https://www.bundesbank.de/en/tasks/payment-systems/services/iban-rules/iban-rules-626476 ; https://www.cfonb.org/fichiers/20140124103020_8_4_RIB_Le_nouveau_Releve_d_Identite_Bancaire_2001_03.pdf ; https://economiapertutti.bancaditalia.it/aree-tematiche/pagamenti/iban/index.html ; https://www.oesterreich.gv.at/de/themen/steuern_und_finanzen/bankgeschaefte/1/1/Seite.750210 ; https://clientebancario.bde.es/pcb/es/blog/que-se-esconde-tras-los-numeros-de-tu-cuenta-corriente-.html ; https://www.betaalvereniging.nl/en/knowledge-base/iban-and-bic/dutch-iban/ ; https://febelfin.be/en/themes/digitalization-innovation/overschrijvingen/a-traditional-bank-transfer ; https://www.wearepay.uk/wp-content/uploads/2018/10/Pay.UK-Standard-Format-of-the-IBAN-issued-in-the-UK-October18-1.pdf ; https://www.abbl.lu/luxembourg-register-of-iban-bic-codes/ | 2026-10-22 |
| R6 (section 10.3.5) | Adresse électronique : forme de la RFC 5321 et bornes de longueur (64 et 255 octets) préférées à la grammaire complète de la RFC 5322 et à ses formes obsolètes | https://www.rfc-editor.org/rfc/rfc5321.txt ; https://www.rfc-editor.org/rfc/rfc5322.txt | 2026-10-22 |
| R6 (section 10.3.9) | Entropie du secret de pseudonymisation (CEPD 01/2025, § 88, note 24) ; donnée pseudonymisée toujours personnelle (RGPD, considérant 26) | https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf ; https://publications.europa.eu/resource/celex/32016R0679 | 2026-10-22 |
| R6 (section 10.8) | Aucune garantie de détection complète (Presidio) ; journal pseudonymisé, donnée personnelle (RGPD art. 4 point 1, LPD art. 5 let. a) | https://presidio.dataprivacystack.org/ ; https://presidio.dataprivacystack.org/evaluation/ ; https://publications.europa.eu/resource/celex/32016R0679 ; https://www.fedlex.admin.ch/filestore/fedlex.data.admin.ch/eli/cc/2022/491/20230901/fr/html/fedlex-data-admin-ch-eli-cc-2022-491-20230901-fr-html-4.html | 2026-10-22 |

### C.7 R7 — Intégrations dans les hôtes

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R7 C-14 | Hôtes secondaires renommés ou déplacés (sources des faits qui fondent ce point) | https://docs.devin.ai/desktop/cascade/mcp ; https://geminicli.com/docs/tools/mcp-server/ ; https://adk.dev/tools-custom/mcp-tools/ ; https://learn.chatgpt.com/docs/extend/mcp | 2026-10-22 |
| R7 F-01 | Claude Desktop : fichier `claude_desktop_config.json`, emplacements macOS et Windows | https://modelcontextprotocol.io/quickstart/user | 2026-10-22 |
| R7 F-02 | Claude Desktop : ouverture du fichier par Settings → Developer → Edit Config | https://modelcontextprotocol.io/quickstart/user | 2026-10-22 |
| R7 F-03 | Claude Desktop : objet `mcpServers` (`command`, `args`, `env`) | https://modelcontextprotocol.io/quickstart/user | 2026-10-22 |
| R7 F-04 | Claude Desktop : redémarrage complet requis, chemins absolus dans `args` | https://modelcontextprotocol.io/quickstart/user | 2026-10-22 |
| R7 F-05 | Claude Desktop : journaux MCP (`mcp.log`, `mcp-server-<nom>.log` pour le `stderr` de chaque serveur) | https://modelcontextprotocol.io/quickstart/user | 2026-10-22 |
| R7 F-08 | Connecteurs personnalisés : connexion depuis l'infrastructure d'Anthropic, pas depuis le poste | https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp | 2026-10-22 |
| R7 F-12 | Extensions de bureau `.mcpb` : installation d'un serveur local en un clic | https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop | 2026-10-22 |
| R7 F-16 | Claude Code : format de `.mcp.json` (`"type": "http"`, `url`, `headers` ; ou `command`, `args`, `env`) | https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R7 F-18 | Claude Code : `claude mcp add --transport http <name> <url> --header …` | https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R7 F-24 | Claude Code : expansion `${VAR}` et `${VAR:-default}` dans `.mcp.json` | https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R7 F-25 | Claude Code : délais `MCP_TIMEOUT`, `MCP_TOOL_TIMEOUT` et `timeout` par serveur | https://code.claude.com/docs/en/env-vars ; https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R7 F-28 | Claude Code : nom complet d'outil de plus de 128 caractères exclu ; approbation par appel exigible par le serveur | https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R7 F-30 | Claude Code : `ANTHROPIC_BASE_URL` redirige les requêtes vers une passerelle | https://code.claude.com/docs/en/env-vars | 2026-10-22 |
| R7 F-31 | Claude Code : `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` et `ANTHROPIC_CUSTOM_HEADERS` | https://code.claude.com/docs/en/env-vars | 2026-10-22 |
| R7 F-32 | Claude Code : configuration d'une passerelle (variables, `settings.json`) et contrôle par `/status` | https://code.claude.com/docs/en/llm-gateway-connect | 2026-10-22 |
| R7 F-33 | Passerelle au format Messages : `/v1/messages`, en-têtes `anthropic-beta` et `anthropic-version` inchangés | https://code.claude.com/docs/en/llm-gateway-protocol | 2026-10-22 |
| R7 F-34 | Claude Code : en-têtes envoyés (`anthropic-version`, identifiants, attribution `x-claude-code-*`) | https://code.claude.com/docs/en/llm-gateway-protocol | 2026-10-22 |
| R7 F-35 | Passerelle : réponse non tamponnée, séquence complète d'événements, `ping` relayés, `retry-after` et `x-should-retry` | https://code.claude.com/docs/en/llm-gateway-protocol | 2026-10-22 |
| R7 F-36 | Passerelle : champs et en-têtes bêta transmis, erreurs amont relayées sans réécriture | https://code.claude.com/docs/en/llm-gateway-protocol | 2026-10-22 |
| R7 F-37 | Claude Code : découverte des modèles par `GET /v1/models` | https://code.claude.com/docs/en/llm-gateway-protocol | 2026-10-22 |
| R7 F-44 | Cursor : fichiers `.cursor/mcp.json` et `~/.cursor/mcp.json` | https://cursor.com/docs/context/mcp | 2026-10-22 |
| R7 F-45 | Cursor : format stdio (`command`, `args`, `env`, `envFile`) | https://cursor.com/docs/context/mcp | 2026-10-22 |
| R7 F-46 | Cursor : format distant (`url`, `headers`) | https://cursor.com/docs/context/mcp | 2026-10-22 |
| R7 F-47 | Cursor : interpolation `${env:NAME}`, `${userHome}`, `${workspaceFolder}` | https://cursor.com/docs/context/mcp | 2026-10-22 |
| R7 F-52 | SDK Agents d'OpenAI (Python) : version 0.24.0, dépendances | https://pypi.org/pypi/openai-agents/json ; https://pypi.org/project/openai-agents/ | 2026-10-22 |
| R7 F-53 | SDK Agents (Python) : classes `MCPServerStdio`, `MCPServerStreamableHttp`, `HostedMCPTool` | https://openai.github.io/openai-agents-python/mcp/ | 2026-10-22 |
| R7 F-54 | SDK Agents (Python) : paramètres de `MCPServerStdio` (`cache_tools_list`, `tool_filter`, …) | https://openai.github.io/openai-agents-python/ref/mcp/server/ | 2026-10-22 |
| R7 F-55 | SDK Agents (Python) : `MCPServerStreamableHttp` et ses paramètres (`url`, `headers`, délais) | https://openai.github.io/openai-agents-python/ref/mcp/server/ | 2026-10-22 |
| R7 F-56 | SDK Agents (Python) : serveur passé à `Agent(mcp_servers=[…])`, exemple avec `Authorization: Bearer` | https://openai.github.io/openai-agents-python/mcp/ | 2026-10-22 |
| R7 F-58 | SDK Agents (Python) : cache de la liste d'outils et `invalidate_tools_cache()` | https://openai.github.io/openai-agents-python/mcp/ | 2026-10-22 |
| R7 F-61 | SDK Agents (Python) : URL de base du modèle par `OPENAI_BASE_URL`, API Responses par défaut | https://openai.github.io/openai-agents-python/config/ | 2026-10-22 |
| R7 F-62 | SDK `openai` (Python) : lecture de `OPENAI_BASE_URL` | https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_client.py ; https://github.com/openai/openai-python | 2026-10-22 |
| R7 F-63 | SDK Agents d'OpenAI (TypeScript) : version 0.21.0, installation | https://registry.npmjs.org/@openai/agents ; https://openai.github.io/openai-agents-js/guides/quickstart/ | 2026-10-22 |
| R7 F-64 | SDK Agents (TypeScript) : types de serveurs MCP (`hostedMcpTool`, Streamable HTTP, stdio) | https://openai.github.io/openai-agents-js/guides/mcp/ | 2026-10-22 |
| R7 F-65 | SDK Agents (TypeScript) : options de `MCPServerStreamableHttp` et `MCPServerStdio` | https://openai.github.io/openai-agents-js/guides/mcp/ | 2026-10-22 |
| R7 F-66 | SDK Agents (TypeScript) : filtrage d'outils, cache et invalidation | https://openai.github.io/openai-agents-js/guides/mcp/ | 2026-10-22 |
| R7 F-67 | SDK Agents (TypeScript) : URL de base par `setDefaultOpenAIClient`, transport WebSocket | https://openai.github.io/openai-agents-js/guides/config/ | 2026-10-22 |
| R7 F-69 | LangChain : `langchain-mcp-adapters` n'est plus maintenu, prise en charge dans `langchain.mcp` | https://raw.githubusercontent.com/langchain-ai/langchain-mcp-adapters/main/README.md ; https://pypi.org/pypi/langchain-mcp-adapters/json | 2026-10-22 |
| R7 F-70 | LangChain, API héritée : `MultiServerMCPClient` | https://github.com/langchain-ai/langchain-mcp-adapters ; https://docs.langchain.com/oss/python/migrate/langchain-mcp-adapters | 2026-10-22 |
| R7 F-71 | LangChain : `from langchain.mcp import MCPAdapter`, `langchain[mcp]>=1.4.0`, bêta | https://docs.langchain.com/oss/python/langchain/mcp | 2026-10-22 |
| R7 F-72 | LangChain 1.4.7 et LangGraph 1.2.16 : versions et dépendances | https://pypi.org/pypi/langchain/json ; https://pypi.org/pypi/langgraph/json | 2026-10-22 |
| R7 F-73 | LangChain : transport inféré de la cible de `MCPAdapter` | https://docs.langchain.com/oss/python/langchain/mcp | 2026-10-22 |
| R7 F-74 | LangChain : configuration multi-serveurs, outils préfixés par la clé de configuration | https://docs.langchain.com/oss/python/langchain/mcp/connections ; https://docs.langchain.com/oss/python/migrate/langchain-mcp-adapters | 2026-10-22 |
| R7 F-75 | LangChain : cycle de vie de `MCPAdapter`, une session par appel d'outil | https://docs.langchain.com/oss/python/langchain/mcp/connections | 2026-10-22 |
| R7 F-79 | LangGraph : `create_react_agent` déprécié au profit de `create_agent` | https://docs.langchain.com/oss/python/releases/langgraph-v1 | 2026-10-22 |
| R7 F-80 | LangChain `ChatOpenAI` : URL de base (`base_url`, `OPENAI_API_BASE`, `OPENAI_BASE_URL`) | https://docs.langchain.com/oss/python/integrations/chat/openai ; https://raw.githubusercontent.com/langchain-ai/langchain/master/libs/partners/openai/langchain_openai/chat_models/base.py | 2026-10-22 |
| R7 F-81 | LangChain `ChatAnthropic` : URL de base (`anthropic_api_url`, `ANTHROPIC_API_URL`, `ANTHROPIC_BASE_URL`) | https://raw.githubusercontent.com/langchain-ai/langchain/master/libs/partners/anthropic/langchain_anthropic/chat_models.py ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_client.py ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/client.ts | 2026-10-22 |
| R7 F-82 | `@langchain/mcp-adapters` 2.0.1 : version et dépendances | https://registry.npmjs.org/@langchain/mcp-adapters ; https://docs.langchain.com/oss/javascript/langchain/mcp | 2026-10-22 |
| R7 F-83 | `@langchain/mcp-adapters` 2.x : `MCPAdapter`, `listTools()` | https://docs.langchain.com/oss/javascript/langchain/mcp | 2026-10-22 |
| R7 F-84 | VS Code (GitHub Copilot) : `.vscode/mcp.json` (`servers`) et format portable `.mcp.json`, secrets par `inputs` | https://code.visualstudio.com/docs/agents/reference/mcp-configuration | 2026-10-22 |
| R7 F-85 | Devin Desktop (ex-Windsurf) : `mcp_config.json`, `serverUrl`, limite de 100 outils | https://docs.devin.ai/desktop/cascade/mcp | 2026-10-22 |
| R7 F-86 | Microsoft Agent Framework : `MCPStdioTool`, `MCPStreamableHTTPTool` (`static_headers`) | https://learn.microsoft.com/en-us/agent-framework/user-guide/model-context-protocol/using-mcp-tools | 2026-10-22 |
| R7 F-87 | Semantic Kernel (Python) : greffons `MCPStdioPlugin`, `MCPSsePlugin`, `MCPStreamableHttpPlugin` | https://learn.microsoft.com/en-us/semantic-kernel/concepts/plugins/adding-mcp-plugins | 2026-10-22 |
| R7 F-88 | Google ADK : `McpToolset` et paramètres de connexion | https://adk.dev/tools-custom/mcp-tools/ | 2026-10-22 |
| R7 F-89 | Gemini CLI : `~/.gemini/settings.json`, `mcpServers`, `httpUrl` | https://geminicli.com/docs/tools/mcp-server/ | 2026-10-22 |
| R7 F-90 | Codex : `~/.codex/config.toml`, tables `[mcp_servers.<nom>]` | https://learn.chatgpt.com/docs/extend/mcp | 2026-10-22 |
| R7 F-91 | Claude Desktop : seul le mode « Claude Desktop on 3P » change l'URL de l'API (`inferenceGatewayBaseUrl`) | https://claude.com/docs/third-party/claude-desktop ; https://claude.com/docs/third-party/claude-desktop/gateway ; https://claude.com/docs/third-party/claude-desktop/in-app-configuration ; https://claude.com/docs/third-party/claude-desktop/configuration | 2026-10-22 |
| R7 NV-01 | Cursor : limite du nombre d'outils MCP absente de la page officielle (non vérifié) | https://cursor.com/docs/context/mcp | 2026-10-22 |
| R7 NV-02 | Cursor : option « Override OpenAI Base URL » absente des pages officielles lues (non documentée) | https://cursor.com/docs/settings/api-keys ; https://cursor.com/docs/models | 2026-10-22 |
| R7 NV-05 | Claude Desktop standard : aucune variable d'URL de base documentée (non documenté) | https://code.claude.com/docs/en/llm-gateway-connect | 2026-10-22 |
| R7 NV-06 | Chemin Linux de `claude_desktop_config.json` : documenté seulement par VS Code (non vérifié chez Anthropic) | https://code.visualstudio.com/docs/agents/reference/mcp-configuration | 2026-10-22 |
| R7 (section 19) | Formats d'intégration des hôtes, lus sur les pages officielles | https://modelcontextprotocol.io/quickstart/user ; https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp ; https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop ; https://code.claude.com/docs/en/mcp ; https://code.claude.com/docs/en/env-vars ; https://code.claude.com/docs/en/llm-gateway-connect ; https://code.claude.com/docs/en/llm-gateway-protocol ; https://cursor.com/docs/context/mcp ; https://pypi.org/pypi/openai-agents/json ; https://pypi.org/project/openai-agents/ ; https://openai.github.io/openai-agents-python/mcp/ ; https://openai.github.io/openai-agents-python/ref/mcp/server/ ; https://openai.github.io/openai-agents-python/config/ ; https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_client.py ; https://github.com/openai/openai-python ; https://registry.npmjs.org/@openai/agents ; https://openai.github.io/openai-agents-js/guides/quickstart/ ; https://openai.github.io/openai-agents-js/guides/mcp/ ; https://openai.github.io/openai-agents-js/guides/config/ ; https://raw.githubusercontent.com/langchain-ai/langchain-mcp-adapters/main/README.md ; https://pypi.org/pypi/langchain-mcp-adapters/json ; https://github.com/langchain-ai/langchain-mcp-adapters ; https://docs.langchain.com/oss/python/migrate/langchain-mcp-adapters ; https://docs.langchain.com/oss/python/langchain/mcp ; https://pypi.org/pypi/langchain/json ; https://pypi.org/pypi/langgraph/json ; https://docs.langchain.com/oss/python/langchain/mcp/connections ; https://docs.langchain.com/oss/python/releases/langgraph-v1 ; https://docs.langchain.com/oss/python/integrations/chat/openai ; https://raw.githubusercontent.com/langchain-ai/langchain/master/libs/partners/openai/langchain_openai/chat_models/base.py ; https://raw.githubusercontent.com/langchain-ai/langchain/master/libs/partners/anthropic/langchain_anthropic/chat_models.py ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_client.py ; https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/client.ts ; https://registry.npmjs.org/@langchain/mcp-adapters ; https://docs.langchain.com/oss/javascript/langchain/mcp ; https://code.visualstudio.com/docs/agents/reference/mcp-configuration ; https://docs.devin.ai/desktop/cascade/mcp ; https://learn.microsoft.com/en-us/agent-framework/user-guide/model-context-protocol/using-mcp-tools ; https://learn.microsoft.com/en-us/semantic-kernel/concepts/plugins/adding-mcp-plugins ; https://adk.dev/tools-custom/mcp-tools/ ; https://geminicli.com/docs/tools/mcp-server/ ; https://learn.chatgpt.com/docs/extend/mcp ; https://claude.com/docs/third-party/claude-desktop ; https://claude.com/docs/third-party/claude-desktop/gateway ; https://claude.com/docs/third-party/claude-desktop/in-app-configuration ; https://claude.com/docs/third-party/claude-desktop/configuration | 2026-10-22 |
| R7 (section 19.5.6) | Formats des autres hôtes (VS Code, Devin Desktop, Microsoft Agent Framework, Semantic Kernel, Google ADK, Gemini CLI, Codex) | https://code.visualstudio.com/docs/agents/reference/mcp-configuration ; https://docs.devin.ai/desktop/cascade/mcp ; https://learn.microsoft.com/en-us/agent-framework/user-guide/model-context-protocol/using-mcp-tools ; https://learn.microsoft.com/en-us/semantic-kernel/concepts/plugins/adding-mcp-plugins ; https://adk.dev/tools-custom/mcp-tools/ ; https://geminicli.com/docs/tools/mcp-server/ ; https://learn.chatgpt.com/docs/extend/mcp | 2026-10-22 |

### C.8 R9 — Antériorité : mandataires et passerelles MCP

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R9 C-09 | Empoisonnement d'outils, « rug pull » et ombrage : empreintes des définitions (sources des faits qui fondent ce point) | https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/main/docs/specs/MCP-SECURITY-GATEWAY-1.0.md ; https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks ; https://invariantlabs.ai/blog/whatsapp-mcp-exploited ; https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ ; https://trailofbits.com/mcp/ ; https://owasp.github.io/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning | 2026-10-22 |
| R9 F-01 | Contrainte officielle sur les noms d'outils MCP (1 à 128 caractères, jeu `[A-Za-z0-9_.-]`), révisions 2025-11-25 et 2026-07-28 | https://modelcontextprotocol.io/specification/2025-11-25/server/tools ; https://modelcontextprotocol.io/specification/2026-07-28/server/tools | 2026-10-22 |
| R9 F-02 | Mandataires qui agrègent plusieurs serveurs : collisions de noms et préfixe par identifiant de serveur (page Tools 2026-07-28) | https://modelcontextprotocol.io/specification/2026-07-28/server/tools | 2026-10-22 |
| R9 F-04 | Nom d'outil dans l'API Messages : motif `^[a-zA-Z0-9_-]{1,128}$`, point exclu | https://platform.claude.com/docs/en/api/messages | 2026-10-22 |
| R9 F-05 | Claude Code : noms complets `mcp__<server>__<tool>`, caractères hors jeu remplacés par `_` | https://code.claude.com/docs/en/permissions ; https://code.claude.com/docs/en/mcp | 2026-10-22 |
| R9 F-12 | Docker MCP Gateway : agrégation de `tools/list` sans préfixe, collisions de noms rejetées | https://raw.githubusercontent.com/docker/mcp-gateway/main/docs/security.md | 2026-10-22 |
| R9 F-63 | TBXark/mcp-proxy : journalisation par client, comportement en panne et point de santé `/_readyz` | https://raw.githubusercontent.com/TBXark/mcp-proxy/master/docs/CONFIGURATION.md ; https://raw.githubusercontent.com/TBXark/mcp-proxy/master/docs/USAGE.md | 2026-10-22 |
| R9 F-82 | Portails MCP de Cloudflare : authentification, journaux, serveur injoignable omis des listes | https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/ | 2026-10-22 |
| R9 F-111 | Aileron : proxy MCP stdio, cadrage par lignes et par `Content-Length` | https://github.com/aileron-sh/aileron ; https://raw.githubusercontent.com/aileron-sh/aileron/main/README.md | 2026-10-22 |
| R9 F-151 | Adjoint confus : définition du « MCP Proxy Server » et consentement par client obligatoire | https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices ; https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices ; https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization | 2026-10-22 |
| R9 F-152 | Relais de jeton (« token passthrough ») : définition, risques pour l'audit, interdiction | https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices ; https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices ; https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization | 2026-10-22 |
| R9 F-153 | Proxys stdio : contrôles recommandés (bac à sable, journalisation, autorisation des commandes) | https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices ; https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices | 2026-10-22 |
| R9 F-160 | Invariant Labs : empoisonnement d'outils, « rug pull » et ombrage (2025-04-01) | https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | 2026-10-22 |
| R9 F-161 | Invariant Labs : exploitation de WhatsApp MCP par ombrage entre serveurs (2025-04-07) | https://invariantlabs.ai/blog/whatsapp-mcp-exploited | 2026-10-22 |
| R9 F-170 | Trail of Bits : « line jumping », attaque par les descriptions d'outils avant tout appel (2025-04-21) | https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ | 2026-10-22 |
| R9 F-181 | OWASP MCP Top 10, MCP03 « Tool Poisoning » : contrôles (signature, empreintes des schémas) | https://owasp.github.io/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning | 2026-10-22 |

### C.9 R10 — Codes d'erreur de MCP, hôtes et motifs de rédaction (révision 0.3)

`MCP@dae694f` désigne le dépôt `modelcontextprotocol/modelcontextprotocol` au
commit `dae694f61a31f7a3ec2af3aff709e11f70f61e48` (2026-10-23), dont les
fichiers cités sont identiques à ceux du commit
`80041ab0a139a8f4fb3adbc99f7ae9113ea59671` lu par CT-3 (R2-F10) ; les URL
suivent la forme
`https://github.com/modelcontextprotocol/modelcontextprotocol/blob/dae694f61a31f7a3ec2af3aff709e11f70f61e48/<fichier>#L<n>`.
Une « mesure de la note » a été faite sur Node.js v22.22.0 (V8 12.4) ou Go
1.24.7 par des scripts non publiés ; elle est reproductible avec les motifs
et les longueurs cités, et n'a pas d'autre source primaire.

| Renvoi | Objet | Source(s) primaire(s) | Consultée le |
|---|---|---|---|
| R10 F-2 | Révision `2026-07-28` : `-32000` à `-32019` hérités (aucune allocation, aucun usage par une implémentation nouvelle, aucun sens supposé par le récepteur sauf `-32002`) ; `-32020` à `-32099` réservés à la spécification | `MCP@dae694f`, `docs/specification/2026-07-28/basic/index.mdx` L109-L127 | 2026-10-23 |
| R10 F-3 | Codes définis `-32020`, `-32021`, `-32022` ; `-32002` et `-32042` ne sont plus émis | `MCP@dae694f`, `docs/specification/2026-07-28/basic/index.mdx` L129-L144 | 2026-10-23 |
| R10 F-4 | Erreurs locales sans code ; code nouveau hors de `-32768` à `-32000` (SHOULD) | `MCP@dae694f`, `docs/specification/2026-07-28/basic/index.mdx` L146-L155 | 2026-10-23 |
| R10 F-5 | Introduction de la qualification « legacy » ; journal des modifications (« grandfathered ») et commentaire du schéma plus souples que le texte normatif | `MCP@dae694f`, commit `205e6c0638a73badb6fcf39a964f7d6c8d61520a` ; `docs/specification/2026-07-28/changelog.mdx` L61-L67 ; `schema/2026-07-28/schema.ts` L407-L425 ; `docs/specification/2026-07-28/index.mdx` L13-L15 | 2026-10-23 |
| R10 F-7 | JSON-RPC 2.0, §5.1 : `-32768` à `-32000` réservés, `-32000` à `-32099` erreurs de serveur définies par l'implémentation, reste de l'espace aux applications | https://www.jsonrpc.org/specification | 2026-10-23 |
| R10 F-9 | Outils : erreurs de protocole (erreur JSON-RPC, MAY au modèle) et erreurs d'exécution (`isError`, SHOULD au modèle) | `MCP@dae694f`, `docs/specification/2026-07-28/server/tools.mdx` L738-L785 | 2026-10-23 |
| R10 F-10 | `CallToolResult.isError` : erreur née de l'outil dans le résultat ; condition exceptionnelle en erreur MCP | `MCP@dae694f`, `schema/2026-07-28/schema.ts` L1823-L1837 | 2026-10-23 |
| R10 F-12 | `structuredContent` conforme à l'`outputSchema` de l'outil | `MCP@dae694f`, `docs/specification/2026-07-28/server/tools.mdx` L498, L509-L515 | 2026-10-23 |
| R10 F-13 | Clés `_meta` : préfixe, notation DNS inversée recommandée, seconds labels `mcp` et `modelcontextprotocol` réservés | `MCP@dae694f`, `docs/specification/2026-07-28/basic/index.mdx` L330-L339 | 2026-10-23 |
| R10 F-15 | CT-2 version 0.2 prenait ses codes dans `-32010` à `-32017` | `spec/CT-2-enregistreur.md` version 0.2 du dépôt public (§4.4, « Codes d'erreur de l'enregistreur », EX-4.24) | 2026-10-23 |
| R10 F-18 | SDK TypeScript 1.32.1 : `callTool` valide `structuredContent` même quand `isError` est vrai (lecture du code, non exécuté) | paquet npm `@modelcontextprotocol/sdk` 1.32.1, `dist/esm/client/index.js` L486-L507 | 2026-10-23 |
| R10 F-21 | SDK Python 1.30.0 : délai local signalé par le code `408`, `CONNECTION_CLOSED = -32000` | https://files.pythonhosted.org/packages/f5/f4/e58bc33317c92a0203664daaf00bf6f41166cc0149e5d6870a03f7cd004a/mcp-1.30.0-py3-none-any.whl (`mcp/shared/session.py` L293-L306, `mcp/types.py` L177-L183) | 2026-10-23 |
| R10 F-22 | openai-agents 0.24.0 : texte fixe au modèle pour une erreur JSON-RPC ; contenu d'un résultat `isError` remis au modèle ; relance sur `-32001`, `408` et `-32000` | https://github.com/openai/openai-agents-python/blob/0dc4cf152bff1f50bdc0e41f28808563406545b2/src/agents/mcp/util.py (L272, L754-L821) ; même commit, `src/agents/tool.py` L1997-L2002, `src/agents/mcp/server.py` L2469-L2477, `src/agents/mcp/_compat.py` L142-L163 | 2026-10-23 |
| R10 F-23 | langchain-mcp-adapters 0.3.2 : résultat `isError` remis au modèle ; erreur JSON-RPC propagée hors de l'outil | https://github.com/langchain-ai/langchain-mcp-adapters/blob/52a4535f3eb4b98f386836e4d9b8c4cadf99afca/langchain_mcp_adapters/tools.py#L99-L158 | 2026-10-23 |
| R10 F-24 | Claude Code : le texte d'un résultat `isError` est le message d'erreur que reçoit le modèle ; rien sur une erreur JSON-RPC | https://code.claude.com/docs/en/mcp.md ; https://code.claude.com/docs/en/errors.md | 2026-10-23 |
| R10 F-25 | OWASP, « Evil Regex » : groupe répété dont le corps contient une répétition ou une alternative qui se recouvre ; `(a+)+$`, `([a-zA-Z]+)*$`, `(a|aa)+$`, `(a|a?)+$` | https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS | 2026-10-23 |
| R10 F-27 | Durées de retour arrière en ECMAScript, motifs exponentiels et polynomiaux sans groupe répété (`[0-9]+$`, `[a-z]*[a-z]*[a-z]*!`) | mesure de la note (Node.js v22.22.0) | 2026-10-23 |
| R10 F-28 | Un quantificateur borné ne protège pas (`(a|aa){1,1000}$`), le drapeau `v` non plus | mesure de la note (Node.js v22.22.0) | 2026-10-23 |
| R10 F-29 | Le paquet `regexp` de Go est linéaire en la longueur de l'entrée, de coût proportionnel à la taille du programme (`[0-9]{1000}x`, 12 047 ms pour 10^6 caractères) | source de la bibliothèque standard de Go 1.24.7, `regexp/regexp.go` L13-L14 ; https://github.com/google/re2/blob/2da0056814cf180480a19f5cf811e7e1c054bf6d/README.md#L9-L20 ; mesure de la note (Go 1.24.7) | 2026-10-23 |
| R10 F-30 | Go et RE2 refusent une répétition imbriquée de plus de 1 000 copies ; divergence avec le contrôle JavaScript de la version 0.2 | source de la bibliothèque standard de Go 1.24.7, `regexp/syntax/parse.go` L435, L442-L473 ; https://github.com/google/re2/blob/2da0056814cf180480a19f5cf811e7e1c054bf6d/re2/parse.cc (L47, L532-L541) | 2026-10-23 |
| R10 F-33 | Moteur non rétrogressif de V8 : expérimental, derrière des options, sans le drapeau `u` | https://v8.dev/blog/non-backtracking-regexp | 2026-10-23 |
| R10 F-34 | Node.js v22.22.0 : drapeau `l` refusé sans option, `lu` refusé avec elle ; changer une option après le démarrage est imprévisible | https://raw.githubusercontent.com/nodejs/node/v22.22.0/doc/api/v8.md (L451-L454) ; mesure de la note | 2026-10-23 |
| R10 F-35 | Sans le drapeau `u`, une classe reconnaît des unités UTF-16 | mesure de la note (Node.js v22.22.0) | 2026-10-23 |
| R10 F-36 | `node:vm` avec `timeout` interrompt une recherche en cours, y compris dans une fonction du contexte principal (environ 0,16 ms par appel) ; `Worker.terminate()` l'arrête en 2 à 3 ms ; `vm` n'est pas une barrière de sécurité | https://raw.githubusercontent.com/nodejs/node/v22.22.0/doc/api/vm.md (L14-L15, L186-L188, L1840-L1851) ; https://raw.githubusercontent.com/nodejs/node/v22.22.0/doc/api/worker_threads.md (L1862-L1879) ; mesure de la note | 2026-10-23 |
| R10 NV-1 | Ce que Claude Code, Claude Desktop ou Cursor montrent au modèle d'une erreur JSON-RPC : non vérifié | https://code.claude.com/docs/en/mcp.md (ne tranche pas) | 2026-10-23 |
| R10 NV-3 | Aucun registre des codes d'application JSON-RPC : l'absence de collision de `-31010` à `-31017` n'est pas vérifiée | https://www.jsonrpc.org/specification (ne tranche pas) | 2026-10-23 |
| R10 NV-4 (levé) | Interruption par `vm` de `replace`, `replaceAll`, `split`, `matchAll`, `match`, `search` et `test` : levée ; avec une borne de 50 ms, arrêt entre 49,5 et 50,8 ms sur `[0-9]+$` et 80 000 chiffres suivis de `x`, contre 4 365 ms (`exec`) et 4 888 ms (`replace`) sans borne | mesure sous Node.js v22.22.0 avec `scripts/lib/capture.mjs` ; test/enregistreur.test.js (EX-10.23, « R10 NV-4 levé ») | 2026-10-23 |
| R10 NV-5 | Coût d'un moteur à automate écrit en JavaScript : non mesuré | https://v8.dev/blog/non-backtracking-regexp (ne tranche pas) | 2026-10-23 |
