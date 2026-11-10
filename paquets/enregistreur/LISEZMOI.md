# @noortrace/enregistreur

Cœur du démon `noortrace`, premier lot de l'étape 4 de la phase 2 : tout ce
qui transforme une capture en événement CT-1 scellé et durable, et la
clôture des périodes, tels que les fixe la spécification normative
[CT-2 version 0.7](../../spec/CT-2-enregistreur.md) (sections 3, 7, 8, 9, 11,
12, 14, 15, 17, annexes A et B), avec [CT-1](../../spec/CT-1-evenements-et-formats.md)
pour les formats et [CT-3](../../spec/CT-3-approbations.md) §12 pour
l'interface du service d'approbation.

Le paquet est écrit à neuf depuis le seul texte de la spécification. Il
importe la bibliothèque noyau [`@noortrace/noyau`](../noyau/LISEZMOI.md) pour
tout ce qu'elle fait (JCS v0, hachage, Ed25519, EIP-191, événement, rotation,
Merkle, manifeste, point de contrôle, dossier, schémas de CT-1) et ne le
réécrit pas. Les vecteurs de `spec/vecteurs/ct-2` et l'annexe A sont le juge.

Le SDK Python et les adaptateurs de cadres sont des lots suivants :
[INTERFACES.md](INTERFACES.md) est leur contrat. La rédaction avant
hachage (§10), le frontal MCP (§4), le moteur de politique (§7.5, 14.2, 14.6),
le frontal modèle (§5), le WORM, le gel juridique et la haute disponibilité
(§12.6, §12.11, §13), le point d'entrée SDK, le SDK JavaScript et l'ingestion
OpenTelemetry (§6) et le branchement du composant d'ancrage de CT-5
(`anchoring.ancrage`, paquet [`@noortrace/ancrage`](../ancrage/LISEZMOI.md))
sont faits (sections « Rédaction avant hachage », « Frontal MCP », « Moteur
de politique », « Frontal modèle », « WORM, gel juridique et haute
disponibilité », « SDK et ingestion OpenTelemetry » et « Ancrage »
ci-dessous).

## Ce que fait le cœur

- **Construction de l'événement** (§7) : événement partiel sorte par sorte
  (appel d'outil relayé, retenu, refusé, reprise ; échange de modèle ;
  décision d'approbation ; rotation ; politique), `policy.redaction` d'après
  les références (EX-10.20), reprise clé pour clé de la `retenue` pour l'appel
  relayé après approbation et le refus d'un ticket décidé (EX-7.12), effets
  par gabarit évalués sur les valeurs rédigées (EX-7.6), validation contre le
  schéma et E-1 à E-7 avant signature (EX-7.1).
- **Écrivain unique** (§3.4, EX-7.8) : `seq`, `ts` (EX-7.9, recul et saut en
  avant d'EX-7.13, mode dégradé « horloge »), `prev_hash`, annonce de
  politique exigée (EX-9.1), pièces exigées sur disque (EX-8.9 ; seule
  exception, révision 0.7 : les pièces perdues d'un événement en attente
  relu au redémarrage, EX-14.18), signature
  vérifiée (EX-11.6), validation groupée (EX-12.7), bail vérifié avant chaque
  signature et chaque fdatasync, puis après (EX-13.6, EX-13.10 (2)).
- **Pièces** (§8) : JCS intégral (§8.1, écrit ici : le noyau ne fait que JCS
  v0), pièces texte, non JSON et non rédigeables (EX-8.7), formes fixes du
  cœur, stockage par `sha256` (fichier temporaire, renommage, fsync du
  fichier et du répertoire, jamais de réécriture, EX-8.9, EX-12.6), espace
  libre minimal (14.2, « disque presque plein »).
- **Segments** (§12.1 à §12.4) : en-tête JCS v0, une ligne JCS v0 par
  événement, rotation par taille et à la frontière de période, relecture
  complète du dernier segment au démarrage, troncature d'une fin incomplète,
  corruption jamais tronquée (EX-12.11).
- **Journal d'intention et reprise** (§12.5) : deux lignes et fdatasync avant
  tout relais d'écriture ou soumis à approbation, levée après durabilité,
  levée implicite, événement de reprise, intention sans contexte, corruption
  (EX-12.12 à EX-12.15, EX-12.22), ordre d'EX-9.8.
- **Périodes et clôture** (CT-1 §9, §10 ; 3.1) : manifeste, signature par la
  clé en vigueur, périodes vides comprises (continuité), nonce frais.
- **Points de contrôle** (§12.10) : instants alignés à 1 s près, point de
  clôture, série en ajout seul, chaînage, reprise de la série, remise au
  composant d'ancrage.
- **Signataires** (§11) : interface commune (EX-11.18) ; enveloppe qui borne
  le message (EX-11.7), applique le délai et une seule seconde tentative,
  vérifie chaque signature (EX-11.6) ; classe D (fichier PKCS#8, chiffré ou
  non), refusée en production (EX-11.8) ; rotation (EX-11.15). Classes A, B
  et C : section « Signataires des classes A, B et C » ci-dessous.
- **Journal sur lui-même** (§9) : événement de politique en tête du journal
  et à chaque changement (EX-9.1, EX-9.2, EX-15.4 pas 6), décision, rotation,
  expiration par le noyau seul (EX-9.4) ; journal d'exploitation NDJSON
  (EX-9.5 à EX-9.7, EX-17.2 à EX-17.4).
- **Interface du service d'approbation, côté démon** (§7.5) : `evaluer` et
  sa validation (EX-7.16), `charger`, `ouvrir`, `decisions` et `acquitter`
  (EX-7.19), `consommer` (EX-7.20), `expiration` ; SG-1 à SG-7 (EX-7.5) ;
  RL-1 à RL-4 (EX-7.21) ; MAC de relais (EX-7.22) ; fichiers des
  approbations (EX-12.23) ; canal HTTP (EX-7.14) ; service factice pour les
  tests (`@noortrace/enregistreur/factice`).
- **Mode dégradé** (§14, pour le cœur) : raisons `stockage`, `cle`, `bail`,
  `horloge`, `attente`, `approbation` ; événements en attente et leur
  scellement (EX-14.8 à EX-14.10, EX-4.46) ; sortie des modes « clé » et
  « stockage » (EX-14.11).
- **Configuration** (§15) : JSON strict, schéma (toutes les erreurs), règles
  hors schéma de la part du cœur, secrets (`env`, `file`), rapport et code 2,
  rechargement de la politique (EX-15.5), commande `validate-config`.
- **Supervision** (§17) : `/healthz`, `/readyz`, `/metrics` ; métriques de
  l'écrivain, de la clé, du bail, du mode dégradé ; contrôles périodiques
  d'EX-17.5 qui ne dépendent pas du WORM (période close, signataire,
  relecture quotidienne des segments fermés avec toutes les clés de la
  chaîne, lecture 153).
- **Export d'un dossier minimal** (CT-1 §11) : douze parties v0 (réservées
  absentes, « hors périmètre CT-1 ») et la treizième, `points-de-controle.json` ;
  avec l'ancrage branché, l'export passe par l'exportateur du composant
  (section « Ancrage ») : parties réservées de CT-5 et CT-4, ancres du point
  couvrant, `entetes-bitcoin.json` à côté.

## Rédaction avant hachage (§10)

Lot « rédaction » (INTERFACES.md, section e) : `redaction*.mjs`, `coffre.mjs`.

- **Politique** (10.2) : document `politique-redaction-v0` validé contre son
  schéma, puis par EX-10.6 (champ et `path`, supprimer, pseudonyme et clé,
  motif nommé existant, identifiants uniques), au démarrage, au rechargement
  et par `validate-config` (`controleRedaction`, pas 3 d'EX-15.4) ; règles
  changées sans changer `redaction.name` refusées (EX-10.21).
- **Motifs** (EX-10.6) : sous-ensemble commun ECMAScript/RE2 par liste
  autorisée (analyseur propre, arbre), règles a) à c), zéro non significatif,
  réécriture des seules ouvertures `(?P<` reconnues, compilation avec le
  drapeau `u` ; contrôle des jetons de la politique motif par motif sous la
  borne (EX-10.23 opération 4) ; même contrôle pour `extract` (EX-7.6).
- **Détecteurs exacts** (10.3) : `iban` (onze pays, MOD 97-10 par blocs),
  `avs` (clé de l'ordonnance, séparateurs identiques), `carte` (Luhn, 12 à 19
  chiffres), `email` (lecture bornée à 64 et 256 caractères autour de chaque
  `@`), `telephone` (8 à 15 chiffres, groupe entre parenthèses), en temps
  linéaire ; `regex` (EX-10.10) ; `champ` (EX-10.11) ; segments entre jetons
  opaques, fin de correspondance frontière (EX-10.9).
- **Application** (10.4) : règles retenues par portée et outil (`<alias>__*`),
  passages jusqu'à stabilité (EX-10.14), idempotence (EX-10.15), `redacted`
  par comparaison des JCS intégraux (EX-10.16), actions `remplacer`,
  `pseudonyme` (HMAC-SHA-256 à clé, EX-10.12) et `supprimer` (10.2.3),
  comptes au journal d'exploitation et aux métriques sans valeur ni position
  (EX-10.17).
- **Pièces** (§8, EX-8.7) : JSON, texte, corps non JSON (UTF-8 rédigé comme
  texte, binaire et codage inconnu non rédigeables), document de contexte ;
  `origine` pour le prompt remplacé dans la requête (EX-8.5) et l'intention
  (EX-10.18).
- **Coût borné** (EX-10.23) : chaque opération sous `node:vm` avec `timeout`
  (`limits.redaction_budget_ms`) ; pièce non rédigeable `budget_redaction`
  (opération 1) et refus `-31010`, raison `redaction`, des arguments d'une
  écriture ou d'un outil susceptible (`bloquerArgumentsNonRedigeables`) ;
  `extract` omis et effet par défaut (opération 2) ; valeur en ligne refusée,
  motif `null` (opération 3).
- **Fils de calcul** (EX-3.6) : groupe borné de `Worker` (au plus 4), garde
  qui arrête et relance un fil ; le fil des entrées-sorties, de l'écrivain et
  du bail reste libre.
- **Valeurs en ligne** : `run_id` (EX-7.2), nom de prompt (EX-8.6), valeur
  quelconque (EX-5.36), effets déclarés par le SDK (EX-6.6), motif d'une
  décision (EX-10.24, crochet `redigerMotif` du cœur).
- **Coffre** (EX-10.22, CT-7 EX-3.11) : désactivé par défaut ; activé,
  homologue AES-256-GCM de chaque pièce rédigée, hors de `storage.root`,
  déchiffrement à deux personnes avec registre des accès hors du coffre.

## Frontal MCP (§4)

Lot « frontal MCP » (INTERFACES.md, section a) : `src/mcp/`, le connecteur
`bin/noortrace-connecteur`. Le frontal est le serveur MCP de l'hôte et le
client MCP de chaque serveur d'outils ; il ne scelle rien lui-même et passe
par les crochets du cœur.

- **Agrégation** (4.3) : nom annoncé `<alias>__<nom d'origine>` ou nom
  d'origine sans préfixe (EX-4.10) ; rejets d'EX-4.11 (`nom_reserve`,
  `nom_invalide`, `collision` y compris sous le gabarit et la normalisation
  de chaque connexion d'hôte, `x_mcp_header` pour un hôte HTTP), consignés
  (`tool_rejected`) ; classe d'EX-14.1 ; empreinte de chaque définition
  annoncée et `tool_definition_changed` (EX-4.16) ; pages de
  `tools.page_size`, curseur opaque, instantané par parcours, liste servie
  par connexion d'hôte (EX-4.13, EX-4.45) ; `ttlMs`, `cacheScope`
  (EX-4.14) ; serveur injoignable omis, santé `serveur:<alias>`, résolution
  sur la dernière liste reçue avec succès (EX-4.18) ; `list_changed` du
  serveur relu au plus une fois par intervalle, `charger`, notification à
  l'hôte qui écoute (EX-4.15).
- **Relais de `tools/call`** (4.4, pas 1 à 14 dans l'ordre d'EX-4.19) :
  lecture JSON stricte à positions (clé en double, substitut isolé, BOM,
  UTF-8 invalide, profondeur et membres bornés), CR rejeté sur une ligne
  (EX-4.43), lot refusé (EX-4.3), nombres d'EX-4.44 ; quotas par connexion
  d'hôte (EX-4.47) ; résolution, pièces de contexte (EX-4.45, EX-7.7) ;
  délégation de 7.2 bornée (EX-7.2) ; corrélation (crochet du frontal
  modèle) ; `evaluer` et matrice de 14.2 pour le service ; pièce
  « arguments » rédigée et durable avant tout relais ; refus, retenue, signal
  d'approbation (EX-4.49), mode `retenir` (EX-4.50) ; RL-1 à RL-4 et
  intention par le cœur ; message amont recopié depuis les octets reçus,
  blancs retirés, `_meta` réécrit (EX-4.7, EX-4.20) ; notifications de
  progression relayées avec le jeton de l'hôte ; délai, annulation, taille,
  perte (EX-4.22, EX-4.23, EX-4.48) ; pièce « résultat » ; événement durable
  avant la réponse, `-31017` après relais (EX-4.46) ; réponse à l'hôte
  recopiée avec `serverInfo` et `resultType` (pas 14) ; continuation MRTR
  sans ticket (EX-4.21) ; codes de la table de 4.4 seulement (EX-4.24).
- **Négociation** (4.2) : hôtes modernes (`_meta` par requête,
  `server/discover`) et hérités (`initialize`, `ping`) ; vers chaque serveur,
  sonde `server/discover` puis repli `initialize`, ou ère épinglée (EX-4.6),
  `subscriptions/listen` vers un serveur moderne.
- **Transports** (4.7) : serveurs stdio lancés par le démon (utilisateur,
  bac à sable, commande épinglée par `sha256` ou paquet, EX-3.4, EX-3.5),
  cadrage par LF, sortie d'erreur consignée par empreinte et débit borné
  (EX-4.32), relance (EX-4.33), arrêt par fermeture de l'entrée, SIGTERM,
  SIGKILL (4.2) ; serveurs Streamable HTTP (en-têtes construits, EX-4.35,
  EX-4.41 ; session héritée, EX-4.38 ; réponse JSON ou SSE) ; prise des
  connecteurs (Unix, TCP à jeton) ; Streamable HTTP vers les hôtes (EX-4.34
  à EX-4.37).
- **Authentification** (4.8) : utilisateur du pair d'une prise Unix (lecture
  31), jeton statique comparé en temps constant, jeton OAuth 2.1 vérifié
  (signature RS256, ES256 ou EdDSA d'une clé du JWKS, audience, émetteur,
  expiration, portées ; métadonnées de ressource protégée, `401` avec
  `WWW-Authenticate`, `403`), aucun relais de jeton (EX-4.41).
- **Journal d'exploitation** (EX-17.2) : `tool_call_relayed`,
  `tool_rejected`, `tool_definition_changed`, `call_blocked`,
  `call_passthrough_pending`, `approval_pending`, `delegation_refused`,
  `definition_non_servie`, `upstream_unreachable`, `upstream_timeout`,
  `child_stderr`, `invalid_line`, `auth_failed`, `stdio_server_command` ;
  jamais un argument, un résultat, un jeton ou un `requestState`.

## Moteur de politique (§7.5, 14.2, 14.6 ; CT-3 §11, §12)

Lot « moteur de politique » (INTERFACES.md, section d) : `src/politique/`.
C'est le point d'appel de CT-3 côté démon ; il ne scelle rien lui-même.

- **Décision au pas 3** (EX-7.4, EX-7.16) : `evaluer` borné par
  `policy.approval.timeout_ms` ; matrice de 14.2 pour le service
  d'approbation (indisponible ou en défaut : bloquant pour une écriture et
  pour tout outil susceptible d'approbation, liste du dernier `charger` réussi,
  tous les outils avant le premier ; passant pour une autre lecture si
  `policy.failure.approval_service.lecture` vaut `passant`, avec `decision:
  "autorise"`, `rule: null` et le défaut consigné) ; classe effective
  d'EX-14.1 ; modes d'attente `erreur` et `retenir` (EX-4.49, EX-4.50, CT-3
  §11), dont l'annulation d'une requête retenue par l'hôte.
- **Mode observation** (EX-4.51, EX-7.23, EX-14.13 à EX-14.17, EX-17.8) :
  réponse sans ticket validée à part (règle réservée ou au-delà de 998
  caractères : invalide), marque ` [observation <x>]` dans `policy.rule`
  (CT-3 EX-6.8), `evaluation impossible [observation inconnu]` sans réponse
  valide ; aucune panne, aucun budget de rédaction, aucun quota ne bloque un
  appel relayable ; événement en attente, ou perdu au-delà des bornes de 14.5
  (`event_lost`) ; jamais `-31017` ; `observation_would_block` et les quatre
  métriques de la révision 0.6 ; entrée en observation refusée avec un ticket
  ouvert (EX-15.8).
- **Boucle `decisions`** (EX-7.19) avec les minuteurs du démon, et
  expirations par le noyau seul à chaque tic hors mode dégradé (EX-9.4),
  différées et consignées pendant un mode dégradé.
- **Validation de `policy.approval.rules`** (EX-15.4 pas 3, CT-3 EX-4.2,
  EX-8.2) : schéma puis points 1 à 7, codes et pointeurs de
  `$defs/code_erreur_politique`, tri de CT-3 annexe A.4 ; avertissements
  d'EX-4.14 qui ne dépendent pas de la liste des outils ; au démarrage, au
  rechargement et par `validate-config`.

## Frontal modèle (§5)

Lot « frontal modèle » (INTERFACES.md, section b) : `src/modele/`. Le
frontal sert les trois modes d'EX-5.1 — passerelle des API de modèle
(5.1.1), serveur ICAP (5.1.2) et récepteur du miroir (5.1.3) — et le
registre de corrélation de 5.6 ; les trois modes partagent un même moteur
d'échanges (`MoteurEchanges` : délégation, colonne M de 14.2, quotas,
pièces, capture de la réponse, scellement). Il ne scelle rien lui-même et
passe par `coeur.ecrirePiece` et `coeur.scellerEchange`.

- **Routes** (EX-5.2, EX-5.28) : chemin normalisé (`%2F`, `.`, `..`, `//`,
  octet hors de l'ASCII imprimable : `400` ; non réservés décodés), comparé
  par égalité ; route `gemini` sur la collection des modèles, segment de
  modèle au motif d'EX-5.28 et méthode `generateContent` ou
  `streamGenerateContent` ; couples `passthrough` relayés sans événement ;
  tout autre couple : `404` (`model_route_not_found`, sans le chemin) ;
  chemin de la route (et cible Gemini reconstruite) seul envoyé à l'amont ;
  chaîne de requête relayée et consignée par son `sha256`, sauf Gemini
  (EX-5.29 : `cle_dans_url`, `flux_sans_sse`, `parametre_non_admis`).
- **Connexion d'hôte** (EX-5.8, EX-7.2, EX-7.3) : jeton statique de
  `model.static_tokens` ou `mcp.http.static_tokens`, par `X-Noortrace-Token`
  ou, en `credentials: "propre"`, par l'en-tête de la route, comparé en temps
  constant ; jeton OAuth (`oauth_subject`, EX-5.8 point 2) d'audience l'URI
  de la passerelle, vérifié par `mcp.http.oauth` (lecture 72) ; en ICAP et
  en miroir, adresse source (`source_addresses`, entrée `"inconnu"`) ; clé du fournisseur de la route (`propre`) ou seul en-tête de la
  route relayé (`relayer`) ; délégation déclarée par `X-Noortrace-Run-Id` et
  `X-Noortrace-On-Behalf-Of`, bornée (motif, détecteurs, liste) ; aucun
  `X-Noortrace-*` relayé.
- **Refus avant relais, sans événement** (EX-5.7, EX-5.26, EX-5.30, EX-5.32,
  EX-5.33) : cadrage `Content-Length` et `Transfer-Encoding`, en-têtes
  d'authentification, de cadrage ou de délégation en double, hôte inconnu
  (`401`), corps au-delà de `model_request_max_bytes` (`413`),
  `Content-Encoding` (`415`), JSON non strict (`400`), serveurs MCP et
  contenu en cache déclarés au fournisseur (`400`, ou relayés et consignés
  sous `relayer`) ; corps d'erreur au format de chaque fournisseur (AIP-193
  pour Gemini, `Content-Type` d'EX-5.30) ; mode dégradé bloquant pour les
  échanges (colonne M de 14.2 : `503`, `call_blocked`), passant en mode
  « stockage » avec `failure.modele: "passant"` et en mode observation
  (EX-14.16 : jamais `noortrace_degrade`).
- **Quotas de la connexion d'hôte** (EX-4.47 ; 14.2, ligne « Mémoire »,
  colonne M) : requêtes en cours, octets reçus (requêtes refusées
  comprises), octets de pièces et temps de capture par minute glissante ;
  au-delà, `503` (`call_blocked`, `reason: "quota"`, `limit_*`), en
  passerelle et en REQMOD, jamais en miroir (lecture 73).
- **TLS** (`model.tls`, EX-5.2 ; ICAPS, EX-5.3) : TLS 1.2 au moins
  (lecture 74) ; certificat ou clé illisible : le démon ne démarre pas.
- **Mode ICAP** (EX-5.3 à EX-5.5, EX-14.12 ; RFC 3507) : services
  `/noortrace/reqmod` et `/noortrace/respmod` sur `model.icap.listen` et
  ICAPS sur `tls_listen` ; `OPTIONS` (`Methods`, `ISTag`,
  `Encapsulated: null-body=0`, `Options-TTL`, aucun `Preview`), `ISTag` sur
  toute réponse, `400`, `403`, `404`, `405`, `501`, `505` ; clients admis par
  mTLS (`client_ca`) ou `allowed_sources` ; `Encapsulated` vérifié (ordre,
  décalages croissants, corps en dernier), corps `chunked` avec `ieof`,
  Preview et `100 Continue`. REQMOD : `X-Noortrace-*` retirés, pièces
  durables, requête modifiée (`200`, jamais `204`) augmentée de
  `X-Noortrace-Exchange: <i>.<m>` ; blocages encapsulés sans événement
  (EX-5.7, colonne M, lectures 73 et 76). RESPMOD : échange retrouvé par
  l'identifiant dont le MAC vérifie, sinon par (méthode, URI, en-têtes,
  instant), sinon pièce `{"noortrace_requete_inconnue": true}` ; réponse
  rendue inchangée chunk par chunk au fil de la réception, analysée en
  parallèle, jamais `204` ; panne après le REQMOD : événement en attente
  (EX-14.12).
- **Mode miroir** (EX-5.6, EX-14.12) : récepteur sur la prise
  `model.mirror.socket` (couples horodatés, lecture 78) et adaptateur de
  capture `bin/noortrace-miroir` (réassemblage HTTP/1.1 de la copie,
  lecture 79) ; connexion d'hôte par l'adresse source ; `is_error` selon le
  statut observé, réponse tronquée : forme incomplète ; rien n'est bloqué ;
  pendant un mode dégradé, l'échange est mis en attente dans les bornes de
  14.5, puis perdu et consigné (`exchange_lost`).
- **Pièces de la requête** (5.3.1 pas 3, 5.5, EX-8.5, EX-8.6) : prompt
  système joint par `\n` format par format, pièce `text/plain` rédigée (ou
  `[PROMPT:<nom>]` en `named`) ; pièce « requête » rédigée, prompt remplacé
  par `[REDIGE:prompt-systeme]` (`reference`) ou rédigé chaîne par chaîne en
  place (`inline`) ; forme inattendue (EX-5.7 point 3) relayée sans pièce
  « prompt système » ; les deux pièces durables avant l'envoi (EX-5.10).
- **Relais** (5.3, EX-5.9, EX-5.11, EX-5.12, EX-5.26) : en-têtes en liste
  autorisée (plus `forward_headers`, moins `strip_headers` et les champs
  saut par saut ; valeurs relayées et notées au journal d'exploitation, noms
  retirés consignés), `Accept-Encoding: identity`, `Content-Length` calculé,
  corps recopié ; réponse relayée octet pour octet dès réception, sans autre
  tampon que la lecture réseau, contre-pression comprise ; réponse comprimée
  quand même (`gzip`, `deflate`, `br`) décomprimée pour la pièce et relayée
  comprimée.
- **Réassemblage des flux** (5.4) : analyseur SSE du HTML Living Standard
  (EX-5.14, `data` final de Gemini d'EX-5.34), formes consolidées
  d'Anthropic, de Chat Completions, de Responses et de Gemini (EX-5.15 à
  EX-5.17, EX-5.35), règles d'EX-5.27 (index, positions, types), événements
  ignorés comptés ; flux incomplet (coupure, délai, hôte parti, borne) marqué
  `noortrace_flux_incomplet`, `is_error` (EX-5.13).
- **Pièce « réponse » et valeurs** (5.3.1 pas 5 et 7, 5.5, EX-5.19 à
  EX-5.21, EX-5.23, EX-5.31, EX-5.33, EX-5.36, EX-8.7) : JSON rédigé, forme
  consolidée, `noortrace_http_error` (Gemini : corps lu quel que soit le
  `Content-Type`), pièce non JSON, non rédigeable (`non_utf8`,
  `codage_inconnu`, `taille`) ou flux brut ; `code.model` tiré de la réponse
  rédigée (repli : requête de forme attendue, ou segment Gemini admis par les
  détecteurs) ; `intent` borné à 4096 caractères ou en pièce, `redacted` si
  une règle l'a modifié.
- **Délais, pas de relance** (EX-5.24, EX-5.25) : connexion, premier octet
  (`504` au format de la route et pièce `noortrace_timeout`), inactivité
  (flux clos, forme incomplète) ; aucune requête réémise.
- **Corrélation** (5.6, EX-5.22) : forme en clair inscrite au registre avant
  que l'hôte reçoive les derniers octets ; même groupe d'hôte, même `run_id`
  si les deux sont déclarés, fenêtre, plus récent d'abord, échange interposé
  préféré à un échange déclaré (`correlation_declaree`), nom par gabarit et
  normalisation, arguments égaux en JCS intégral, appel du modèle consommé
  une fois ; `intent` du texte qui précède l'appel dans la réponse rédigée.
- **Événement** : `noortrace.modele.echange` scellé après la réponse ; une
  panne après l'envoi met l'événement en attente (14.2, EX-14.8) ; arrêt
  propre qui laisse finir les échanges en cours (13.5).
- **Journal d'exploitation et métriques** (EX-17.2) : `model_exchange_relayed`,
  `model_request_refused`, `model_route_not_found`, `model_passthrough`,
  `provider_error`, `provider_mcp_bypass`, `provider_cache_reference`,
  `model_segment_refused`, `model_response_truncated`,
  `sse_data_final_sans_ligne_vide`, `host_disconnected`, `call_blocked`,
  `auth_failed`, `delegation_refused`, `correlation_declaree`,
  `observation_would_block`, `tls_refused`, `model_gateway_listening`,
  `model_icap_listening`, `model_mirror_listening`, `icap_request_refused`,
  `icap_exchange_refused`, `icap_correlation_heuristique`,
  `icap_requete_inconnue`, `icap_respmod_non_capture`,
  `mirror_line_refused`, `exchange_lost` ;
  `noortrace_model_tokens_total`, `noortrace_upstream_latency_ms`,
  `noortrace_upstream_errors_total`, `noortrace_relay_latency_ms` ; jamais
  un corps, un prompt, un jeton ou une clé.

## WORM, gel juridique et haute disponibilité (§12.6, §12.11, §13)

Lot « WORM et haute disponibilité » (INTERFACES.md, section f) : `src/worm/`,
`src/ha/`, `bin/noortrace-ctl`, `bin/noortrace-attributs`.

- **Requêtes exactes** (EX-12.39) : encodage RFC 3986 octet par octet,
  en-têtes triés, corps XML de S3 et `Content-MD5` (RFC 1864), Azure
  (`x-ms-version: 2020-06-12`) et GCS (JSON en JCS intégral), sans réseau.
- **Couche d'accès S3** écrite sur `node:crypto` (SigV4, contrôlée sur les
  exemples publiés par AWS) ; adresse « virtual-hosted » sans `endpoint`,
  « path » avec (lecture 81) ; délai de 10 s ; essais d'EX-12.40.
- **Copies de l'écrivain** (EX-12.16) : chaque segment fermé (par taille, à
  la frontière de période, ou par sa seule existence à la reprise), chaque
  manifeste, signature et série des points d'une période close, les
  fichiers d'ancres et, avec `copy_pieces`, les pièces référencées ; clé
  `<prefix>` + chemin de 12.1 ; `PUT` conditionnel à l'absence avec
  `Content-MD5`, sans rétention (EX-12.30), gel à l'écriture avec
  `legal_hold_on_write` (EX-12.31) ; jamais sous `<prefix>gels/` (EX-12.32) ;
  segment d'époque inférieure au dernier scellé refusé (EX-13.5 (2)) ;
  contrôle du verrou de la version écrite (EX-12.33) ; registre des copies
  `worm/copies-<epoch>.ndjson` (EX-12.29) ; échec consigné
  (`worm_copy_failed`), jamais bloquant, réessayé par le balayage.
- **Supervision** (EX-17.5 à EX-17.7) : contrôles horaires (SHA-256 de
  chaque copie de l'heure ; manifeste, signature, continuité et signataire
  sont contrôlés par le cœur, avec ou sans WORM, lecture 153),
  quotidiens (rétention par défaut du support, registre des gels et état
  `on` des versions des gels actifs ; la relecture des segments fermés de
  la journée, avec toutes les clés de la chaîne, est au cœur), relevé de verrouillage tous les
  `lock_audit_interval_days` jours (versions inattendues, marqueurs,
  versions sans ligne au registre inscrites) ; lignes `integrity_check`,
  `worm_lock_check`, `worm_lock_config_check`, `worm_lock_audit`,
  `worm_versions_unexpected`, `worm_legal_hold_observed` ; métriques
  `noortrace_worm_*` et `noortrace_integrity_check_failures_total`.
- **Gel juridique** (12.11) : `noortrace-ctl worm gel poser`,
  `demander-levee`, `lever`, `reprendre`, `etat`, hors du démon, avec les
  identifiants de l'exploitant (refus de ceux de l'écrivain, code 2) ;
  périmètre (EX-12.35), registre des gels écrit sur le support par
  écriture conditionnelle avant et après les requêtes (EX-12.37), règle de
  garde des deux personnes vérifiée sur le registre relu avant toute
  requête de levée (EX-12.38), versions couvertes par un autre gel actif
  laissées gelées (`results.kept`, EX-12.40), relecture après chaque
  requête, codes de sortie 0 à 4, lignes `worm_legal_hold_*` sans identité
  d'exploitant. `noortrace-ctl worm releve` : relevé à la demande (EX-17.6).
- **Reconstruction depuis les copies** (EX-12.17, CT-8 §11.4 chemin B,
  EX-10.14) : `noortrace-ctl worm reconstruire` liste les versions sous
  `<prefix>` (EX-17.6 pas 1), relit la version inscrite au registre des
  copies (`--registre-copies`, archive du chemin A) ou, sans registre, la
  version unique de chaque clé, contrôle le SHA-256 et la longueur de
  chaque objet relu contre le registre, écrit dans un répertoire neuf
  (jamais sur l'original), recrée `journal.json`, vérifie la chaîne
  (continuité des `seq`, `prev_hash`, en-têtes, époques, manifestes
  recalculés) et liste les fichiers perdus (intentions, attente,
  approbations, pièces sans `copy_pieces`) ; tout incident (copie absente,
  altérée, plusieurs versions sans registre, segment manquant) : rien n'est
  écrit, code 1 (`worm_restore_refused`). Le démon reprend ensuite sur ce
  répertoire avec une époque plus grande (13.4). `noortrace-ctl worm
  restaurer <clé> --version <id>` relit une version, compare son SHA-256 au
  registre et l'écrit dans un répertoire neuf (EX-10.14).
- **Compagnon des attributs** (EX-12.18, CT-8 EX-3.9) :
  `bin/noortrace-attributs --racine <storage.root> [--intervalle-s <1 à
  60>]`, processus distinct du démon, sous le compte 0 avec
  `CAP_LINUX_IMMUTABLE` : `a` sur le segment courant et le journal
  d'intention, `i` sur chaque segment fermé et chaque manifeste (et sa
  signature), à chaque passage ; un segment fermé d'époque inférieure au
  dernier scellé n'est pas scellé (EX-13.5 (2)) ; `noortrace-attributs
  sonde` pour la santé du service (CT-8). Le démon garde son descripteur
  ouvert ; un fichier d'intention levé qu'il ne peut plus supprimer
  (attribut `a`) est gardé et consigné (`intention_file_kept`).
- **Magasins de bail** (13.2) : `postgresql` (protocole écrit sur
  `node:net`/`node:tls` : SCRAM-SHA-256, MD5, TLS ; requête étendue à
  paramètres, jamais d'interpolation), `etcd` v3 (passerelle JSON) ;
  validité sur l'horloge monotone (EX-13.3), fil de renouvellement, perte
  consignée (`lease_lost`) et mode dégradé « bail » (EX-13.6), vérification
  après fdatasync (EX-13.10 (2), `lease_lost_after_write`).
- **Bascule** (13.4) : clé du MAC de relais comparée avant toute
  acquisition (`relay_mac_key_mismatch`) ; instance passive
  (`lease_standby`, santé `standby`, `-31010 bail_non_detenu`, aucun échange
  avec le service d'approbation), nouvel essai toutes les `renew_ms` ;
  prise du bail avec une époque plus grande, relecture, reprise des
  intentions ; taille des fichiers d'époque inférieure consignée
  (`lease_predecessor_files`) et fourche signalée (`journal_fork`,
  EX-13.10 (3)) ; fichiers d'intention et d'attente refusés sous une époque
  supérieure présente dans le répertoire du journal (EX-13.5 (1), lecture
  188) ; une instance sans bail ou d'époque dépassée n'écrit rien ; un démon
  qui perd son bail se relance et redevient passif (13.4 pas 8) ;
  `instance_id` dans `data` du journal d'exploitation avec `postgresql` ou
  `etcd` (EX-17.2, lecture 190).

## SDK et ingestion OpenTelemetry (§6)

Lot « SDK et OpenTelemetry » (INTERFACES.md, section c) : `src/sdk/`,
`src/otel/`, et le SDK JavaScript `noortrace-sdk` (`paquets/sdk-js/`, son
LISEZMOI). Les deux chemins sont **déclaratifs** (6.1, 6.7) : ils ne voient
rien passer sur le réseau ; le démon n'en scelle que ce que le processus de
l'agent déclare, marqué comme tel dans l'événement.

- **Point d'entrée SDK** (6.2, EX-6.1) : prise Unix `sdk.socket` (mode 0660,
  utilisateur du pair lu comme pour le connecteur stdio, lecture 31) ou prise
  TCP `sdk.tcp_listen` (jeton statique en première ligne, sur TLS si `tls`
  est posé ; ou mTLS : certificat client de l'autorité qui suit le
  certificat du démon dans `tls.cert_file`, rattaché par son nom commun à
  `match.peer_user`, lecture 113) ; une ligne JSON-RPC
  par message (4.7.1) ; entrée de `sdk.hosts` de l'identité, délégation et
  groupe d'hôte de la configuration, `run_id` et `on_behalf_of` déclarés et
  bornés (EX-7.2) ; sessions liées à leur connexion, identifiants jamais
  réutilisés.
- **Méthodes `noortrace/sdk/*`** : `ouvrir` ; `declarerContexte` (pièce de
  contexte rédigée, portée `contexte`, citée par son `sha256` dans la même
  session seulement) ; `debutAppel` (pas 2 à 8 de 4.4 : validation
  d'EX-6.6 par -32602 sans pièce ni événement, nom `<alias>__<tool>`, classe
  de la table de 6.2, corrélation de 5.6 pour `code.model` et
  `code.prompt_version`, `intent` déclaré rédigé, politique par le moteur de
  politique, table d'EX-6.7 — refus, retenue, en attente, approuvé avec RL-1 à
  RL-4 —, pièce « arguments », effets déclarés rédigés, intention durable
  avant la réponse pour une écriture ou un ticket approuvé) ; `finAppel`
  (pièce « résultat », événement durable avant `{ seq, hash }`, `-31017` après
  une panne) ; `echangeModele` (formats v0, `gemini` d'EX-6.8 et `autre`,
  pièce de déclaration de source en `context[0]`, échange déclaré inscrit au
  registre de corrélation) ; `fermer`.
- **Reprise** (EX-12.15, EX-6.13) : une session fermée ou dont la connexion
  est perdue, le démon tournant, donne l'événement de reprise de chaque
  `debutAppel` resté ouvert qui a écrit une intention (à chaud, par le cœur) ;
  le démon arrêté, la relecture du journal d'intention le fait au démarrage.
- **Pannes et observation** (14.2, 14.5, 14.6) : matrice de 14.2 pour le SDK
  (écriture bloquée, lecture passante en mode « stockage », événement en
  attente) ; mode observation : rien ne bloque un appel, marque
  ` [observation …]`, `observation_would_block`.
- **Ingestion OpenTelemetry** (6.8) : OTLP/HTTP sur `otel.listen` (`POST` sur
  `otel.path`, TLS avec `otel.tls`), ordre des décisions d'EX-6.27, gzip
  borné avant allocation, quotas de la source et bornes propres
  (`spans_per_request`, `events_per_minute`, `event_bytes_per_minute`,
  `min_free_bytes`) ; décodage JSON (nombres lus sur leur texte) et protobuf
  (écrit à neuf sur l'encodage proto3, refus des formes ambiguës) vers une
  même représentation ; forme normalisée d'EX-6.31 ; classification ;
  doublons (fenêtre, 1 000 000 de clés, conflits) et recouvrement avec le
  frontal MCP, le frontal modèle et le SDK (registre nourri par les
  scellements du cœur) ; pièces d'EX-6.35 (déclaration de source, requête,
  réponse, prompt système, intention, arguments, résultat, enveloppe rédigée
  sur ses seuls membres textuels, bornes de taille et de temps) ; événement
  d'EX-6.36 remis à l'écrivain après les événements des autres frontaux ;
  réponse `200` (ou succès partiel) quand tous sont durables ; `503` sans
  événement en attente pendant un mode dégradé (EX-6.39).
- **Configuration** (EX-15.4 pas 3) : `controleSdk` (alias du SDK, `policy.sdk`,
  EX-6.24) et `controleOtel` (sources, jetons, alias, `policy.otel`, TLS hors
  bouclage en production, avertissements d'EX-6.34 et d'EX-6.27).
- **Journal d'exploitation et métriques** (EX-17.2, EX-6.41) : composant `sdk`
  (`sdk_listening`, `sdk_connected`, `sdk_session_opened`, `sdk_session_closed`,
  `sdk_call_started`, `sdk_call_finished`, `sdk_exchange_declared`,
  `sdk_effects_declared`, `sdk_member_removed`, `sdk_input_refused`,
  `sdk_class_override_refused`, `sdk_recovery_deferred`, `call_blocked`,
  `call_passthrough_pending`, `delegation_refused`, `auth_failed`) ; composant
  `otel` (`otel_listening`, `otel_request`, `otel_refused`,
  `otel_span_rejected`, `otel_span_overlap`, `otel_span_conflict`,
  `otel_piece_too_large`, `otel_cle_double`, `otel_dedup_evicted`,
  `delegation_refused`, `auth_failed`) ; `noortrace_relay_latency_ms{path="sdk"}`,
  `noortrace_otel_requests_total`, `noortrace_otel_spans_total`,
  `noortrace_otel_conflicts_total`, `noortrace_otel_reception_lag_ms` ; jamais
  un argument, un contenu de span ni un jeton.

## Signataires des classes A, B et C (§11)

Lot « signataires » (`src/signataires/`, INTERFACES.md rubrique j). La
fabrique `signataireDepuisConfiguration` rend le backend de
`signer.backend.type` ; l'enveloppe commune vérifie chaque signature
(EX-11.6), borne le message (EX-11.7), applique `signer.timeout_ms` et une
seule seconde tentative (EX-11.18).

| Classe | Backend | Requêtes (identité d'usage seule, EX-11.4) | Authentification | Éprouvé contre |
|---|---|---|---|---|
| A | `pkcs11` | `C_GetFunctionList`, `C_Initialize`, `C_OpenSession` (lecture seule), `C_Login` (CKU_USER), `C_FindObjects` (CKO_PUBLIC_KEY / CKO_PRIVATE_KEY, CKK_EC_EDWARDS, CKA_LABEL), `C_GetAttributeValue` (CKA_EC_PARAMS, CKA_EC_POINT, CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_SIGN), `C_SignInit` (`CKM_EDDSA` 0x1057 sans paramètre) puis `C_Sign` en une partie | PIN (référence de secret), passé à l'auxiliaire par son entrée standard | SoftHSM2 2.6.1 réel (paquet Ubuntu 24.04), les deux formes de CKA_EC_PARAMS |
| B | `vault-transit`, `openbao-transit` | `GET /v1/<mount>/keys/<nom>`, `POST /v1/<mount>/sign/<nom>` `{input, key_version}` | `X-Vault-Token` (référence de secret), `X-Vault-Namespace` | Vault 1.20.4 et OpenBao 2.4.3 réels (conteneurs épinglés par condensé), jeton d'usage d'une politique « lire la clé, signer » |
| B | `aws-kms` | `GetPublicKey`, `Sign` (`MessageType: RAW`, `ED25519_SHA_512`), `DescribeKey` ; JSON 1.1, SigV4 `kms` | variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (lecture 182) | simulateur écrit pour les tests : LocalStack 4.0.3 rend `InternalError` à `CreateKey` `ECC_NIST_EDWARDS25519` (essayé) |
| B | `gcp-kms` | `GET …/publicKey`, `POST …:asymmetricSign` (`data`, `dataCrc32c`), `GET` de la version | jeton OAuth d'un compte de service (assertion JWT RS256) | simulateur écrit pour les tests (aucun émulateur de Cloud KMS) |
| C | `envelope` + `aws-kms` | `Decrypt` (`EncryptionContext` : `org_id`, `journal_id`, `key_id`) | comme `aws-kms` | LocalStack 4.0.3 réel (`Encrypt`/`Decrypt`, contexte appliqué) |
| C | `envelope` + `gcp-kms` | `POST …:decrypt` (`additionalAuthenticatedData` = JCS du contexte, CRC32C) | comme `gcp-kms` | simulateur |
| C | `envelope` + `azure-keyvault` | `POST …/keys/<nom>/<version>/unwrapkey?api-version=7.4` (`RSA-OAEP-256`, `A256KW`, `CKM_AES_KEY_WRAP`) | application Entra ID par secret client (`AZURE_*`) | simulateur (`RSA-OAEP-256`, `A256KW` ; `CKM_AES_KEY_WRAP` non éprouvé) |
| C | `envelope` + `tpm2` | `tpm2_createprimary`, `tpm2_load`, `tpm2_unseal -p pcr:<pcrs>` (tpm2-tools) | politique PCR | swtpm 0.7.3 et tpm2-tools 5.6 réels (TCTI `swtpm`) |

Au démarrage (EX-15.4 pas 5) : clé publique lue, comparée à celle
qu'annonce la chaîne pour la clé courante (lecture 183), signature de test
vérifiée, ligne `signer_ready` (classe, backend, identifiant de clé,
identifiant chez le backend ; jamais un secret, EX-11.8) ; un backend
injoignable, une clé refusée (type, exportable, extractible) ou une graine
indéchiffrable refusent le démarrage (`demarrage_refuse : cle : …`, code 2).
En service : `health()` toutes les `signer.health_interval_ms` ; un échec,
une signature qui ne vérifie pas, un délai dépassé deux fois mettent le
démon en mode dégradé « clé » (bloquant pour tout ; `-31017` pour un appel
déjà relayé, dont l'événement est gardé en attente) ; la sortie exige
`health()` réussi et une signature de test (EX-14.11). Rotation planifiée
au tic (lecture 184) ; en classe C, les graines sont effacées à l'arrêt
(EX-11.9).

## Ancrage (CT-5)

Le composant d'ancrage de CT-5 est branché par `src/ancrage-demon.mjs`
(`preparerAncrage`, `BranchementAncrage`) quand `anchoring.ancrage` désigne
un document `ancrage-v0` ; `anchoring.ancrage` `null` : aucun composant,
comportement inchangé (la remise d'`ancrage.mjs` reste l'interface vue du
cœur).

- **Démarrage** (§15.4, pas 4 ; CT-5 EX-4.8, EX-4.9) : le document est lu en
  JSON strict, ses références de secrets (`auth.secret` des prestataires,
  `headers_source.auth`) sont résolues par `resoudreSecret` (`env`, `file`,
  `vault`), la clé de chaîne de `anchoring.registry.chain_key` est
  construite (classe D, `SignataireChaineFichier` du composant, adresse
  confrontée), le manifeste d'instance du registre est lu dans
  `instance-registre.json` à côté du document (lecture 199), puis le
  composant est construit sur un contexte dont tout vient du stockage
  (séries `points/`, manifestes, segments, index des clés, époque du bail)
  et démarré après l'écrivain (`anchoring_attached`). Une clé de chaîne de
  classe A, B ou C refuse le démarrage du démon :
  `demarrage_refuse : ancrage : classe_cle_chaine : …` (code 2 ; étape 7,
  lecture 200). Tout autre défaut laisse le démon démarrer : points et
  manifestes sont produits, `anchoring_not_started` est consigné avec la
  raison (`document_illisible`, `configuration_invalide` et les règles d'AN-1
  en défaut, `secret_non_resolu` et le pointeur, `instance_registre_absente`,
  `rpc_url_absente`, `demarrage_impossible`) et chaque remise donne
  `anchor_pending` (lecture 197).
- **Horloge, journal, métriques** (§7.4, §17.2) : l'horloge du cœur étendue
  de `programmer` ; le journal d'exploitation (composant `ancrage`) ;
  `/metrics` expose `noortrace_anchor*` d'EX-8.15 avec les métriques du cœur.
- **Remises** (EX-12.27) : `remettrePoint`, `remettreCloture` rendent la
  main sans attendre le réseau (CT-5 EX-4.12 ; §14.2).
- **Clôture au registre** (CT-4 §8.2) : `submitPeriod` est relayé quand la
  demande signée au seuil par les approbateurs est déposée sous
  `<journal>/registre/demande-cloture-<period_hash>.json` ; sinon
  `period_close_delegated` (`signatures_en_attente`) et reprise au tic
  (lecture 198).
- **Rechargement** (EX-15.5) : `noortrace-ctl reload` recharge le document
  `ancrage-v0` après la politique (`config_reloaded` du composant ; un
  document invalide est refusé, l'ancien reste). La ligne `config_reloaded`
  du cœur porte, comme `startup`, le `sha256` des octets du document de
  configuration et le `policy_sha256` (EX-18.6 ; corrigé par les épreuves
  CT-9 de l'étape 5, éprouvé par `test/enregistreur-journal-soi.test.js`, TE-14).
- **Export** (CT-1 §11, CT-5 §10) : `Coeur.exporterDossier(seq, destination)`
  passe par l'exportateur du composant quand il est démarré (`dossier_exported`) ;
  `Coeur.reexportsDus()` liste les dossiers qu'une ancre arrivée depuis rend
  à réexporter (EX-10.5) ; un dossier remis n'est jamais modifié. Le
  branchement ne garde que le résumé du dernier dossier de chaque événement,
  sans retenue du texte d'`acquisitions.ndjson` (corrigé par les épreuves
  CT-9 de l'étape 5 : 2 799 exports d'une période à `c_T` 60 s épuisaient le
  tas du démon ; éprouvé par `test/ancrage-exportateur.test.js` et
  `test/enregistreur-ancrage-exigences.test.js`).
- **Copie WORM** (EX-12.27 ; CT-5 EX-5.15, EX-8.14) : le service de copies
  couvre `ancres/` (pièces, `acquisitions.ndjson`, `entetes-bitcoin.json`) et
  la file `file-<epoque>.ndjson` sous `queue.path` quand il est sous le
  répertoire du journal, par la règle des fichiers fermés (lecture 93).
- **`noortrace-ctl ancrage etat | metriques | retirer-qualification <id>`** :
  même canal que `cle rotation-urgence` (fichier de demande et SIGURG,
  lecture 201) ; réponse au journal (`anchoring_state`, `anchoring_metrics`,
  `provider_qualification_withdrawn` ; refus `anchoring_ctl_refused`).
- **Arrêt** : `anchoring_stopped` après la fermeture de l'écrivain, avant
  `shutdown`.
- **Essais** : `test/enregistreur-ancrage-parcours.test.js` (TE-12 : démon
  réel enfant du test à horloge réglable, hors réseau public ; variante sur le
  réseau de développement, en attente quand il n'est pas debout),
  `test/enregistreur-ancrage-exigences.test.js`,
  `test/enregistreur-ancrage-corrections-h1.test.js` (R-G-1) ; le composant
  lui-même suit CT-5 révision 0.5 et CT-6 révision 0.5 (`LISEZMOI.md` du
  composant, « Vecteurs rejoués »).
- **Restes** : clé de chaîne de classe A à C (étape 7) ; rotation d'urgence
  au registre (`registre_non_branche`, lecture 202) ; clé
  `anchoring.registry.instance` à inscrire dans CT-2.

## Démarrer le démon

```sh
noortrace validate-config configuration.json    # pas 1 à 3 d'EX-15.4 ; code 0 ou 2
noortrace --config configuration.json           # démarre ; SIGTERM, SIGINT : arrêt propre ; SIGHUP : rechargement
```

Avec un magasin de bail `postgresql` ou `etcd` détenu par une autre instance,
le démon démarre en instance passive (`standby`) et prend le bail dès qu'il
est libre (13.4). Le gel juridique et le relevé à la demande :

```sh
noortrace-ctl worm gel poser --configuration configuration.json --identifiants '{"file":"/run/secrets/gardien-pose"}' --identite j.dupont --de 1794304800 --a 1794304800 --motif "Litige LT-0042"
noortrace-ctl worm gel demander-levee --configuration configuration.json --identifiants '{"file":"/run/secrets/gardien-pose"}' --identite j.dupont --gel <gel_id> --motif "Litige clos"
noortrace-ctl worm gel lever --configuration configuration.json --identifiants '{"file":"/run/secrets/gardien-levee"}' --identite m.keller --gel <gel_id> --demande <empreinte>
noortrace-ctl worm gel etat --configuration configuration.json --identifiants '{"file":"/run/secrets/lecteur"}' --gel <gel_id>
noortrace-ctl worm releve --configuration configuration.json
noortrace-ctl worm reconstruire --configuration configuration.json --vers /var/lib/noortrace-restaure --registre-copies /sauvegarde/worm
noortrace-ctl worm restaurer <clé d'objet> --version <version_id> --configuration configuration.json --vers /var/lib/noortrace-version
noortrace-attributs --racine /var/lib/noortrace --intervalle-s 60     # compte 0, CAP_LINUX_IMMUTABLE (EX-3.9 de CT-8)
noortrace-attributs sonde                                             # code 0 si le dernier passage a réussi et est récent
noortrace-ctl reload [--configuration configuration.json]            # EX-15.5 : SIGHUP au démon, réponse lue au journal d'exploitation
noortrace-ctl clock --accept [--configuration configuration.json]    # EX-7.13 : confirmation après un saut d'horloge en avant, consignée
noortrace-ctl cle rotation-urgence [--configuration configuration.json]   # EX-11.16 (CT-8 EX-10.14), lecture 194
noortrace-ctl cle rapprocher --configuration configuration.json --audit audit.log   # CT-7 EX-3.7, lecture 195 ; code 3 : incident
noortrace-ctl ancrage etat [--configuration configuration.json]                     # CT-5 : état du composant d'ancrage, au journal (anchoring_state)
noortrace-ctl ancrage metriques [--configuration configuration.json]                # noortrace_anchor* lues sur /metrics de la supervision
noortrace-ctl ancrage retirer-qualification <id> [--configuration configuration.json]   # CT-5 EX-5.9 : retrait de `qualified`, relève des demandes en cours
```

`noortrace-ctl reload` et `clock --accept` n'ouvrent aucune prise (EX-18.1) :
ils trouvent le démon de leur utilisateur et lui envoient un signal (lecture
152) ; codes 0 fait, 1 refusé par le démon, 2 usage, 4 aucun démon ou pas de
réponse.

Avec `mcp.enabled`, le démon démarre ensuite le frontal MCP : serveurs
d'outils stdio lancés et listés, prise `mcp.socket` des connecteurs, prise
`mcp.connector_tcp` et Streamable HTTP `mcp.http` s'ils sont configurés.
L'hôte lance le connecteur comme serveur MCP stdio (19.5.1) :

```sh
noortrace-connecteur --socket /run/noortrace/mcp.sock
```

Sur la prise TCP `mcp.connector_tcp` : `noortrace-connecteur --tcp
127.0.0.1:<port>`, avec `NOORTRACE_CONNECTEUR_JETON` (jeton, sur TLS si
`NOORTRACE_CONNECTEUR_TLS_CA` est posé), ou en mTLS
`NOORTRACE_CONNECTEUR_TLS_CA`, `NOORTRACE_CONNECTEUR_TLS_CERT` et
`NOORTRACE_CONNECTEUR_TLS_KEY` (lectures 134 et 135).

Avec `model.mode: "passerelle"`, le démon écoute aussi sur `model.listen` :
l'hôte y pose l'URL de base de son SDK (`ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL`, `httpOptions.baseUrl`) et son jeton statique ou OAuth.
Avec `model.mode: "icap"`, il sert les deux services ICAP sur
`model.icap.listen` (et ICAPS sur `tls_listen`) ; le mandataire du client
transmet l'adresse de l'hôte par l'en-tête `client_address_header`. Avec
`model.mode: "miroir"`, il écoute sur la prise `model.mirror.socket`, où
l'adaptateur de capture remet les couples :

```sh
noortrace-miroir --socket /run/noortrace/miroir.sock --ecoute 127.0.0.1:9100
```

L'adresse d'écoute effective de chaque mode est consignée au journal
d'exploitation (`model_gateway_listening`, `model_icap_listening`,
`model_mirror_listening`) ; le registre de corrélation est remis au frontal
MCP. Un frontal qui ne peut pas écouter (adresse prise, certificat
illisible) empêche le démarrage : `demarrage_refuse : frontal_modele :
<cause>`, code 2. Une clé de chaîne d'une classe que ce lot ne sert pas
l'empêche aussi : `demarrage_refuse : ancrage : classe_cle_chaine : <cause>`
(section « Ancrage »).

Avec `sdk.enabled`, le démon écoute sur la prise `sdk.socket` (ou
`sdk.tcp_listen`) les méthodes `noortrace/sdk/*` ; un agent Node.js y parle
par `noortrace-sdk` (`NOORTRACE_SDK_SOCKET`). Avec `otel.enabled`, il sert
OTLP/HTTP sur `otel.listen` ; l'exportateur de l'agent y est dirigé par
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces` et
`OTEL_EXPORTER_OTLP_TRACES_HEADERS=x-noortrace-token=<jeton de la source>`
(6.8.15). Les adresses effectives sont consignées (`sdk_listening`,
`otel_listening`) ; une prise ou une adresse impossible empêche le
démarrage : `demarrage_refuse : sdk` ou `demarrage_refuse : otel`, code 2.

Une configuration invalide n'est jamais servie : une ligne par erreur sur
stderr (`config_invalid : <pointeur JSON> : <règle> ; valeur : <valeur>`, sans
la valeur pour un secret) et code de retour 2. Au démarrage, dans l'ordre
d'EX-15.4 et d'EX-9.8 : stockage, bail, clé publique et signature de test,
relecture et troncature, reprise des intentions, événements en attente,
événement de politique (refus de démarrer si l'ensemble a changé sans changer
`policy.version`, EX-10.21), fichiers des approbations, `charger`, `ouvrir`,
`consommer`, ligne `startup`, supervision, minuteurs (points, clôtures,
remises).

## Configuration

Le document unique de §15, validé contre `configuration-enregistreur-v0`
(copie dans `schemas/`, avec `politique-redaction-v0`,
`politique-approbation-v0`, `ticket-v0` et `evenement-v0` ; un test les
compare à `spec/schemas`). Le cœur lit : `recorder`, `signer` (classe D :
`backend.type: "file"`, `path`, `passphrase`), `storage` (`root`,
`segment_max_bytes`, `min_free_bytes`, `fsync`, `relay_mac_key`, `seal.worm.prefix`),
`lease` (`file`), `clock`, `checkpoint_interval_s` (défaut 60),
`supervision`, `limits.pending_max_bytes`, `tools.default_timeout_ms`,
`mcp.hosts` et `sdk.hosts` (reprise d'une intention sans contexte),
`policy` (ensemble de politique, version, gabarits d'effets, classes,
`approval` pour SG-4, SG-7, RL-4, EX-9.4, `failure.pending_max_events`),
`anchoring.ancrage` (chemin du document `ancrage-v0` de CT-5, ou `null`) et
`anchoring.registry` (`enabled`, `rpc_url`, `chain_key` : classe D servie,
`address`, `secret`) ; le manifeste d'instance du registre est lu dans
`instance-registre.json` à côté du document d'ancrage (lecture 199).

Règles hors schéma vérifiées par ce lot (EX-15.4 pas 3) : classe et backend
du signataire, classe D en production, `verify_after_sign`, alias
`noortrace`, `tools.prefix`, cadence des points, `lease.renew_ms <
lease.ttl_ms / 2`, `fencing` en production, rétention et WORM (EX-12.19,
EX-12.30, EX-12.31), clé de chaîne de classe D en production, gabarits
d'effets, chemins des routes, jetons statiques, `otel`, mode `retenir`, mode
observation (EX-15.8), approbateurs de test. Le lot WORM ajoute
`controleWorm` (avertissement si `storage.seal.worm.credentials` est la même
référence qu'un autre secret) et lit `storage.seal.worm` en entier ; le lot
de haute disponibilité lit `lease` en entier (`store` `file`, `postgresql`
avec `dsn` et `table`, `etcd` avec `endpoints`, `prefix`, `tls`).

## Fichiers sur disque

Sous `storage.root/<org_id>/<journal_id>/` (hexadécimal sans `0x`, EX-12.1) :

| Fichier | Écrit par | Forme |
|---|---|---|
| `journal.json` | création du journal, une fois | `{ version, org_id, journal_id, created_at, recorder }` |
| `segments/seg-<first_seq:16>-<epoch:20>.ndjson` | écrivain | en-tête JCS v0, puis une ligne JCS v0 par événement (12.2) |
| `pieces/<xx>/<sha256>` | `ecrirePiece` | octets de la pièce |
| `intentions/intentions-<epoch:20>.ndjson` | écrivain | lignes JCS intégral : intention, contexte, levée (12.5) |
| `attente/attente-<epoch:20>.ndjson` | mode dégradé, au mieux | `{ pending_id, captured_at, event, pieces, intent_id }` (14.5) |
| `approbations/approbations-<epoch:20>.ndjson`, `mac-<epoch:20>.ndjson` | noyau | lignes de EX-12.23 ; ligne de contrôle du MAC en tête |
| `manifestes/periode-<period_start:10>.json`, `.sig` | clôture | `JSON.stringify(objet, null, 2)` + `\n` |
| `points/periode-<period_start:10>.ndjson` | points de contrôle | une ligne JCS intégral par point signé |
| `worm/copies-<epoch:20>.ndjson` | copies WORM (lot WORM) | une ligne JCS intégral `$defs/ligne_copie` par copie contrôlée (EX-12.29) ; ajout seul, sans fdatasync propre |
| `ancres/periode-<period_start:10>/rfc3161/*`, `ots/*`, `entetes-bitcoin.json`, `acquisitions.ndjson` | composant d'ancrage (CT-5 EX-5.14, EX-6.8, EX-5.13) | jetons, requêtes, réponses, CRL, preuves, nonces, en-têtes, enregistrements d'acquisition (ajout seul) ; copiés au WORM une fois fermés |
| `ancres/file/file-<epoch>.ndjson` (si `queue.path` y est placé) | composant d'ancrage (CT-5 EX-8.5) | file durable, une ligne JCS intégral par état d'une demande ; copiée quand son époque est fermée |
| `registre/envoi-*.json`, `issue-*.json`, `bloc-*.json`, `recu-*.json`, `certificat-*.json`, `capture-*.json` | composant d'ancrage (CT-4 §8.6, §9.4) | envois et captures du registre ; `demande-cloture-<period_hash>.json` y est déposée par l'exploitant (lecture 198) |

Hors du répertoire du journal : la table ou la clé du magasin de bail
`postgresql` ou `etcd` (13.2), le verrou du bail `file` (`lease.store.path`,
fichier jamais supprimé ni lu : seul compte le verrou `flock(2)` posé dessus,
lecture 148) et son époque (`<path>.epoch`), le journal d'exploitation
(`supervision.ops_log.path`, rotation par taille), le coffre des originaux
s'il est activé (`storage.vault.path/<sha256 de la pièce rédigée>` : nonce
de 12 octets, chiffré AES-256-GCM, étiquette de 16 octets) et le registre
des accès au coffre (un fichier NDJSON choisi par l'exploitant, hors du
coffre). Il n'y a aucun fichier
d'état mutable : l'état de l'écrivain et les index (tickets, décisions,
politiques, clés) se dérivent des segments à la reprise.

## Modules

| Module | Domaine | Sections |
|---|---|---|
| `configuration.mjs`, `schema.mjs`, `secrets.mjs` | chargement, validation, secrets | §15, EX-15.1 à EX-15.8 |
| `capture.mjs`, `effets.mjs` | capture → événement | §7.1 à §7.4, EX-7.6, EX-7.12 |
| `jcs-integral.mjs`, `pieces.mjs` | pièces | §8 |
| `ecrivain.mjs`, `segments.mjs`, `fichiers.mjs` | écrivain unique, segments, durabilité | §3.4, §12.1 à §12.4 |
| `intentions.mjs` | journal d'intention | §12.5 |
| `reprise.mjs`, `index-chaine.mjs` | relecture, reprise | EX-12.10, EX-12.14, EX-9.8 |
| `periodes.mjs` | périodes et clôture | CT-1 §9, §10 ; 3.1 |
| `points.mjs` | points de contrôle | §12.10 |
| `signataires.mjs` | signataires (interface, enveloppe commune, classe D) | §11 |
| `signataires/fabrique.mjs`, `signataires/commun.mjs` | fabrique des backends, requêtes bornées, SPKI, CRC32C, contexte de chiffrement | §11, EX-15.4 pas 5 |
| `signataires/pkcs11.mjs`, `signataires/pkcs11-auxiliaire.py` | classe A : PKCS#11 par un auxiliaire (python3, ctypes) | EX-11.10 |
| `signataires/transit.mjs`, `signataires/aws-kms.mjs`, `signataires/gcp-kms.mjs` | classe B : Vault et OpenBao Transit, AWS KMS, Google Cloud KMS (et leurs enveloppes pour AWS et Google) | §11.2, EX-11.1, EX-11.5, EX-11.7 |
| `signataires/enveloppe.mjs`, `signataires/azure.mjs`, `signataires/tpm2.mjs` | classe C : graine enveloppée ; Azure `unwrapKey` ; descellement TPM 2.0 | EX-11.9 |
| `signataires/rapprochement.mjs` | rapprochement des signatures (`noortrace-ctl cle rapprocher`) | CT-7 EX-3.7 |
| `secrets-vault.mjs` | références de secrets `{ "vault" }` (lecture KV au démarrage et au rechargement) | 15.2 |
| `bail.mjs` | bail (interface, magasin `file` : `flock(2)` tenu par `flock(1)`, lecture 148) | §13 (part du cœur), 13.2 |
| `verification.mjs` | vérification complète d'un répertoire de journal (segments, signatures avec les clés de la chaîne, manifestes, séries, pièces) | EX-12.10 pas 2, EX-12.17, CT-8 EX-11.6 |
| `controles.mjs` | contrôles périodiques d'EX-17.5 hors WORM (période close, signataire, relecture quotidienne) | EX-17.5 |
| `ctl-demon.mjs`, `bin/noortrace-ctl` | `noortrace-ctl reload`, `noortrace-ctl clock --accept`, `noortrace-ctl cle rotation-urgence`, `noortrace-ctl ancrage etat|metriques|retirer-qualification` | EX-15.5, EX-7.13, EX-18.1 ; CT-5 EX-5.9 |
| `lui-meme.mjs` | journal sur lui-même | §9.1 |
| `journal-exploitation.mjs` | journal d'exploitation | §9.2, §17.3 |
| `supervision.mjs`, `degrade.mjs`, `horloge.mjs` | supervision, mode dégradé, horloge | §17, §14, §7.4 |
| `approbations.mjs`, `service-approbation-http.mjs`, `service-approbation-factice.mjs` | interface du service d'approbation | §7.5, §12.9, CT-3 §12 |
| `ancrage.mjs`, `worm.mjs` | remise à l'ancrage, copies WORM (interfaces) | §12.10, §12.6 |
| `ancrage-demon.mjs` | branchement du composant d'ancrage de CT-5 : document `ancrage-v0`, secrets, clé de chaîne, manifeste d'instance, contexte depuis le stockage, `signaturesCloture`, rechargement, export, réexports, commandes `noortrace-ctl ancrage` | §15.4 pas 4, EX-11.19, EX-12.27 ; CT-5 §4.4, §10 ; CT-4 §8.2 |
| `dossier.mjs` | export d'un dossier minimal ; `assemblerBase` et délégation à l'exportateur du composant d'ancrage | CT-1 §11 ; CT-5 §10 |
| `redaction-motifs.mjs` | sous-ensemble des motifs, règles a) à c), borne de temps | EX-10.6, EX-10.23 |
| `redaction-detecteurs.mjs` | détecteurs exacts | §10.3 |
| `redaction-moteur.mjs`, `redaction-fil.mjs` | application des règles, pièces, valeurs en ligne ; fil de calcul | §10.4, §8, EX-3.6 |
| `redaction.mjs` | rédacteur, crochets du cœur, contrôles de configuration, groupe de fils | §10, EX-15.4 |
| `coffre.mjs` | coffre des originaux | EX-10.22, CT-7 EX-3.11 |
| `mcp/json-texte.mjs` | lecture JSON stricte à positions, recopie sans blancs, nombres d'EX-4.44 | 4.4 pas 1, EX-4.20, EX-4.43, EX-4.44 |
| `mcp/agregation.mjs` | noms annoncés, rejets, classes, pages | §4.3, EX-14.1 |
| `mcp/amont.mjs` | connexions aux serveurs d'outils (stdio, Streamable HTTP) | §4.2, §4.7, EX-3.4, EX-3.5, EX-4.6 |
| `mcp/frontal.mjs`, `mcp/messages.mjs`, `mcp/quotas.mjs`, `mcp/delegation.mjs` | sessions d'hôte, `tools/list`, `tools/call`, erreurs, quotas, délégation | §4.4, §7.2, §14.1 à §14.3 |
| `mcp/hote-stdio.mjs`, `mcp/connecteur.mjs`, `bin/noortrace-connecteur` | prise des connecteurs, connecteur stdio | §4.7.1, EX-4.39 |
| `mcp/prise-tcp.mjs` | prise TCP authentifiée commune (`mcp.connector_tcp`, `sdk.tcp_listen`) : TCP ou TLS avec jeton, mTLS | EX-4.39, EX-6.1, lectures 113, 134 |
| `mcp/hote-http.mjs` | Streamable HTTP des hôtes, OAuth | §4.7.2, §4.8 |
| `mcp/demon.mjs` | frontal dans le démon | §3.4 |
| `politique/moteur.mjs` | décision au pas 3, matrice de 14.2 (service), modes d'attente, mode observation, boucle `decisions`, EX-15.8 | §7.5, §14.2, §14.6, CT-3 §11, §12 |
| `politique/regles.mjs` | validation de `policy.approval.rules`, avertissements | EX-15.4 pas 3, CT-3 EX-4.2, EX-4.14, EX-8.2 |
| `modele/formats.mjs` | routes, normalisation, chaîne de requête Gemini, corps d'erreur, en-têtes, prompt système, règles de configuration | §5.1.1, §5.2, §5.3, EX-5.28 à EX-5.32, EX-8.5, EX-15.4 |
| `modele/flux.mjs` | analyseur SSE, formes consolidées | §5.4 |
| `modele/extraction.mjs` | pièces de la requête et de la réponse, `code.model`, `intent`, appels demandés | 5.3.1, §5.5, EX-5.21, EX-5.31, EX-5.33, EX-5.36, EX-8.7 |
| `modele/correlation.mjs` | registre de corrélation | §5.6 |
| `modele/echange.mjs` | moteur d'échanges commun aux trois modes : délégation, colonne M, quotas, pièces, capture de la réponse, scellement, attente | 5.3.1, §5.4, EX-4.47, §14.2 (colonne M), EX-14.12 |
| `modele/passerelle.mjs` | passerelle HTTP(S) : réception, connexion d'hôte (jeton statique, OAuth), relais, délais | §5.1.1, §5.3, §5.7, EX-5.8, §13.5 |
| `modele/icap.mjs` | serveur ICAP et ICAPS (RFC 3507) : OPTIONS, REQMOD, RESPMOD | §5.1.2, EX-5.3 à EX-5.5, EX-14.12 |
| `modele/miroir.mjs`, `bin/noortrace-miroir` | récepteur de la prise du miroir, adaptateur de capture | §5.1.3, EX-5.6, EX-14.12 |
| `modele/demon.mjs` | frontal modèle dans le démon, selon le mode | §3.4, EX-5.1 |
| `worm/requetes.mjs`, `worm/verrou.mjs`, `worm/perimetre.mjs`, `worm/garde.mjs` | requêtes exactes, contrôle du verrou, périmètre d'un gel, règle de garde, gels actifs, versions à lever (sans réseau) | EX-12.33, EX-12.35, EX-12.37 à EX-12.40, EX-17.7 |
| `worm/s3.mjs`, `worm/xml.mjs`, `worm/bearer.mjs`, `worm/support.mjs` | couches d'accès (SigV4, jeton porteur), réponses XML de S3, opérations par support, essais | §12.6, EX-12.34, EX-12.39, EX-12.40 |
| `worm/copies.mjs`, `worm/registre.mjs` | copies de l'écrivain (`SupportWorm`), registre des copies, pièces référencées | EX-12.16, EX-12.29 à EX-12.33, EX-13.5 (2) |
| `worm/controles.mjs` | contrôles périodiques, relevé, lecture du registre des gels | EX-17.5 à EX-17.7 |
| `worm/gel.mjs`, `worm/ctl.mjs`, `bin/noortrace-ctl` | outil de gel juridique, relevé à la demande | §12.11, EX-17.6 |
| `worm/configuration.mjs` | règle `controleWorm`, fabrique du service de copies | EX-15.4 pas 3 |
| `worm/restauration.mjs` | reconstruction du journal depuis les copies, restauration d'une version | EX-12.17, CT-8 §11.4 chemin B, EX-10.14 |
| `worm/attributs.mjs`, `bin/noortrace-attributs` | compagnon des attributs `a` et `i`, sonde | EX-12.18, CT-8 EX-3.9 |
| `ha/bail-reseau.mjs`, `ha/postgresql.mjs`, `ha/pg-protocole.mjs`, `ha/etcd.mjs` | magasins de bail `postgresql` et `etcd`, protocole PostgreSQL, passerelle JSON d'etcd | §13.2, EX-13.3, EX-13.4, EX-13.6, EX-13.10 (2) |
| `ha/cloture.mjs`, `ha/index.mjs` | jeton de clôture des fichiers, clé du MAC avant le bail, fourche ; fabrique des magasins | EX-13.5 (1), EX-13.10 (3), 13.4 |
| `sdk/validation.mjs` | paramètres des méthodes `noortrace/sdk/*`, refus -32602 | §6.2, EX-6.6 |
| `sdk/frontal.mjs` | sessions, `ouvrir` à `fermer`, classe, corrélation, politique, pièces, intention, reprise à chaud, pannes | §6.2, §6.3, EX-6.3, EX-6.7, EX-12.15, §14 |
| `sdk/echange.mjs` | échange de modèle déclaré (formats v0, `gemini`, `autre`) | 6.2, EX-6.8, EX-7.7 |
| `sdk/prise.mjs`, `sdk/limiteur.mjs`, `sdk/demon.mjs` | prise Unix et TCP, identité, limitation des échecs, point d'entrée dans le démon | EX-6.1, EX-6.10, EX-18.3 |
| `sdk/configuration.mjs` | règles du pas 3 pour `sdk` et `policy.sdk` | EX-15.4, EX-6.24 |
| `otel/decodage-json.mjs`, `otel/decodage-protobuf.mjs` | décodage OTLP/JSON et protobuf | EX-6.29, EX-6.30 |
| `otel/representation.mjs` | forme normalisée, classification | EX-6.31, EX-6.32 |
| `otel/tables.mjs` | doublons, recouvrement | EX-6.33, EX-6.34 |
| `otel/projection.mjs` | pièces et événement d'un span | EX-6.35, EX-6.36 |
| `otel/ingestion.mjs`, `otel/reponses.mjs`, `otel/serveur.mjs` | ordre des décisions, bornes, quotas, réponses, OTLP/HTTP | EX-6.26 à EX-6.28, EX-6.37 à EX-6.41 |
| `otel/configuration.mjs`, `otel/demon.mjs` | règles du pas 3 pour `otel`, ingestion dans le démon | EX-15.4, EX-6.40 |
| `coeur.mjs`, `cli.mjs`, `bin/noortrace` | assemblage, démarrage, démon | §3, §15.4, §15.6 |

## Ce qui relève des lots suivants

Part du frontal modèle non faite : réassemblage HTTP/2 de la copie du
miroir (EX-5.6 : non couvert par la version 0, section 21) ; traducteurs des
formats de copie des équipements réels vers les trames de l'adaptateur
(lecture 79) ; part du lot SDK et
OpenTelemetry non faite : OTLP/gRPC (non servi en version 0, EX-6.26) ; notifications de
progression pendant une rétention (EX-4.50, CT-3 EX-11.6, facultatives) ; part du
frontal MCP non faite : relais hors chaîne de 4.5 (`resources/*`,
`prompts/*`, `completion/complete` : `-32601`), requêtes du serveur vers le
client et `sampling` en échange de modèle (4.6, EX-4.29 : refusées par
`-32601` côté serveur hérité, `inputRequests` non déclarées refusées par
`-31016`), continuation MRTR d'un appel approuvé (EX-4.21 : la ré-émission
repasse par le pas 3, échec fermé), client OAuth vers un serveur d'outils
(EX-4.40, EX-4.42 : refusé à la connexion), `prctl(PR_SET_DUMPABLE)` (EX-3.5, sans module natif) ;
part du lot des signataires non faite : valeur de `CKM_CLOUDHSM_EDDSA`
(lecture 176), identité managée Azure, identifiants de conteneur et de
fédération, adresse par défaut d'IMDS (lectures 182, 193), lecture de la clé
inscrite au registre et pas du registre de la rotation d'urgence (lectures
183, 194), rapprochement sur CloudTrail et Cloud Audit Logs (lecture 195) ;
purge des pièces (EX-12.20, et donc sa
suspension pendant un gel) ; image `noortrace/attributs` du compagnon
(étape 7 : le programme `noortrace-attributs` est prêt) ; procès-verbal
`restauration` de CT-8 (11.9) ; part du lot WORM non faite : copie, liste des
versions, lecture et écriture d'un objet sur Azure et Google Cloud Storage,
que CT-2 0.5 ne fixe pas (lecture 84), et donc le gel sur ces supports
au-delà des requêtes de gel et de lecture d'état ; part de l'ancrage (CT-5)
et du registre (CT-4) non faite : clé de chaîne de classe A à C (EX-11.19,
étape 7 : le démon refuse de démarrer avec une telle classe), rotation
d'urgence relayée au registre (`registre_non_branche`, lecture 202), outil
d'export hors démon ; exportateur complet de CT-6 ; démonstration (§19).

## Lectures de passages ambigus

Chaque lecture est tranchée par le texte et, quand un vecteur la porte, par
le vecteur ; l'implémentation de référence n'a pas été consultée.

1. **Délégation d'une décision d'approbation.** CT-2 7.2, table
   `delegation`, colonne « Événements du journal sur lui-même » :
   `"noortrace-enregistreur"`, `scope "journal:administration"` ; mais la
   table `code` met la décision à part (« décision : ceux de l'appel
   retenu »), et le vecteur `evenements/journal-demo` (seq 6) comme CT-1
   annexe A (seq 3) portent la délégation de l'appel retenu. Lecture : la
   décision reprend la délégation et `code.model`, `code.prompt_version` de
   la `retenue` ; politique et rotation portent la délégation du journal.
2. **Ligne invalide d'un segment : troncature ou corruption** (EX-12.10 pas 2
   et 3 contre EX-12.11). EX-12.10 dit que « la première ligne invalide ou
   incomplète » marque la fin du contenu durable ; EX-12.11 réserve la
   troncature à « une fin de fichier incomplète (ligne sans \n ou JSON
   inachevé) ou [aux] octets nuls de remplissage ». Lecture : seule une
   dernière ligne sans `\n`, ou faite d'octets nuls (jusqu'à la fin), est
   tronquée ; toute autre ligne invalide (hash, signature, chaînage, schéma,
   ligne illisible suivie d'autres) est une corruption : `segment_corrupted`,
   mode dégradé « stockage », aucune écriture jusqu'à intervention.
3. **`ts` après une clôture.** EX-7.9 : `ts = max(ts lu, ts précédent)` ;
   EX-7.11 : « la clôture d'une période n'a lieu qu'après le dernier
   événement dont le `ts` lui appartient ». Un recul de l'horloge sous le
   seuil, après une clôture sans événement nouveau, donnerait un `ts` dans
   une période close. Lecture : l'écrivain prend aussi pour plancher
   `period_end` de la dernière période close.
4. **Première période et périodes vides.** CT-1 §10.1 : `first_seq = 1` pour
   la première période ; §10.3 : continuité. Lecture : la première période
   est celle du `ts` de seq 1 (l'événement de politique, écrit au
   démarrage) ; chaque heure suivante a son manifeste, vide ou non, y compris
   les heures d'un arrêt, closes à la reprise avec un point de clôture
   (`tree_size` = 0 pour une période vide).
5. **Rotation de segment à la clôture** (EX-12.4 (a), EX-13.9). Un segment
   qui n'a reçu aucun événement n'est pas tourné à la clôture (sinon un
   segment réduit à son en-tête par heure) ; chaque démarrage ouvre un
   segment neuf (nouvelle époque), comme EX-13.9 le dit.
6. **Magasin de bail `file`** (13.2 : `flock(LOCK_EX | LOCK_NB)`).
   Remplacée par la lecture 148 (verrou `flock(2)` tenu par `flock(1)`).
   Un bail perdu exige un redémarrage (EX-13.6 interdit la reprise « à
   chaud » sans relecture).
7. **Clé suivante de classe D.** 15.1 nomme `signer.rotation.next_key_id` sans
   dire où est son fichier. Lecture : même répertoire que
   `signer.backend.path`, nom `<next_key_id>` suivi de l'extension du fichier
   courant ; même phrase de passe.
8. **Signature de test** (EX-15.4 pas 5, EX-14.11) et EX-11.18 (« aucun autre
   message n'est jamais soumis au signataire »). Lecture : le message de test
   est `P_S` seul, de la forme `P_S ‖ C` avec `C` vide, qu'aucun événement ne
   peut produire (sa forme canonique n'est jamais vide).
9. **Signature d'une clé dont la clé publique est inconnue à la relecture.**
   Remplacée par la lecture 154 : une telle ligne n'est plus acceptée
   sans vérification (`segment_corrupted`, raison `cle_inconnue`).
10. **SG-4 et `approval.at`** (EX-7.5, EX-7.11). SG-4 porte sur « l'instant
    d'écriture de la décision, qui sera `approval.at` », connu seulement quand
    l'écrivain fixe `ts`. Lecture : SG-4 est vérifiée avant le scellement à
    l'instant courant, puis de nouveau au `ts` fixé ; un `ts` au-delà de
    l'échéance annule le scellement (`acquitter` `refuse`,
    `echeance_depassee`).
11. **Pointeur ou littéral dans un gabarit d'effets** (EX-7.6 : « pointeur JSON
    RFC 6901 dans les arguments ou le résultat (`/arguments/...`,
    `/result/...`), ou chaîne fixe »). Lecture : une chaîne est un pointeur si
    et seulement si elle commence par `/arguments` ou `/result` (suivi de `/`
    ou en fin) ; une autre chaîne commençant par `/` est refusée à la
    validation.
12. **Fichiers de période.** 12.1 nomme `manifestes/periode-<period_start>.json`
    et `.sig` sans fixer leurs octets. Lecture : `JSON.stringify(objet, null,
    2)` suivi d'un saut de ligne, la mise en forme des parties de dossier de
    CT-1 §11.1, de sorte que l'exportateur les copie octet pour octet.
13. **`checkpoint_ts` d'un point.** CT-1 §10.5 : instant de production. Le
    point de clôture est produit après `period_end` : son `checkpoint_ts` vaut
    `generated_at` du manifeste (≥ `period_end`). Un `checkpoint_ts` n'est
    jamais antérieur au point précédent ni à `period_start`.
14. **Annonce d'une version déjà annoncée** (EX-10.21 : « Le changement DOIT
    s'accompagner d'une nouvelle valeur de `policy.version` »). Lecture : un
    ensemble dont la version a déjà été annoncée avec une autre empreinte est
    refusé ; un retour à un ensemble déjà annoncé, même version et même
    empreinte, est annoncé de nouveau.
15. **Fichier d'attente après scellement.** 14.5 ne dit pas quand le fichier
    `attente-<epoch>` est retiré. Lecture : au démarrage, les fichiers des
    époques antérieures sont scellés puis supprimés ; un arrêt pendant ce
    scellement peut sceller une seconde fois un événement en attente (perte
    admise, consignée par `pending_flushed`).
16. **`cles.json` exporté.** CT-1 §11.2 laisse `source` libre et la validité de
    la clé initiale « telle qu'annoncée ». Lecture : la clé initiale est
    valide depuis `created_at` de `journal.json`, chaque rotation ferme la
    précédente et ouvre la suivante à son `ts` (CT-1 §8 règle 3) ; `source`
    nomme `journal.json` et les rotations.
17. **Événements partiels et EX-9.1.** Un événement en attente, de reprise ou
    d'un appel commencé avant un rechargement porte la `policy_version` de sa
    capture ; l'écrivain refuse toute version jamais annoncée dans le journal.
18. **Délai de `consommer`.** CT-3 §12.7 dit « nouvel essai, idempotent » sans
    borne : le cœur réessaie cinq fois (200 ms, 400 ms…) puis au prochain
    démarrage (EX-7.20).

Lectures du lot « rédaction » (§10) :

19. **Types de jetons « employés »** (EX-10.6, EX-10.9 : « chaque nom de motif
    nommé et chaque étiquette `champ` employés »). `pii-v1` déclare
    `numero-sinistre` sans l'employer dans une règle. Lecture : les types de
    jetons sont les cinq détecteurs nommés, `prompt-systeme`, **tous** les
    motifs nommés déclarés et les étiquettes `champ` des règles ; un jeton
    d'un motif déclaré reste opaque. Aucun vecteur ne dépend de ce choix.
20. **« Faire correspondre un jeton »** (EX-10.6). Lecture : le motif trouve
    une correspondance non vide n'importe où dans la chaîne du jeton
    (`REDIGE` ou `0{12}` sont refusés), pas seulement sur le jeton entier :
    c'est ce qui protège un jeton d'une réécriture partielle.
21. **Motif nommé après une correspondance remplacée** (EX-10.9 : « la fin
    d'une correspondance remplacée vaut frontière […] comme le `]` du
    jeton »). Lecture : la recherche reprend sur le reste du segment comme
    sur une chaîne nouvelle (`\b` y voit une frontière, `^` y correspond),
    ce que voit de toute façon le passage suivant, où ce reste est un segment
    (bord de segment = début de chaîne) ; le résultat après passages est le
    même.
22. **IBAN groupé** (10.3.2 pas 1 : « en admettant entre deux d'entre eux un
    SEP isolé », caractères lus « à partir de `p+4` »). Le vecteur
    `iban-groupes-valide` (`CH93 0076 …`) exige un SEP entre `KK` et le
    premier caractère du BBAN. Lecture : un SEP isolé est admis entre deux
    alphanumériques quelconques du candidat après `CC KK`, jamais entre `CC`
    et `KK`.
23. **Dernier label d'un domaine** (10.3.5 : « le dernier fait d'au moins deux
    lettres ASCII »). Lecture : fait uniquement de lettres ASCII, au moins
    deux (`x@exemple.c1` n'est pas rédigé).
24. **Comptes de `supprimer`** (EX-10.17, B.3 `matches`). Le vecteur
    `supprimer-membre` compte `{ detector: "champ", count: 1 }`. Lecture :
    une suppression compte un `champ` ; un élément de tableau déjà égal au
    jeton n'est ni remplacé ni compté. Les comptes sont rendus dans l'ordre
    de leur première apparition, passages compris (vecteur
    `passages-multiples`).
25. **Note d'un pointeur qui ne résout pas** (10.2.1 : « une note dans le
    journal d'exploitation »). EX-17.2 ne la nomme pas. Lecture : ligne
    `redaction_path_unresolved` (portée, règle), une par règle et par pièce.
26. **Coffre** (EX-10.22). Le format du fichier et la forme des données
    associées ne sont pas fixés. Lecture : fichier = nonce ‖ chiffré ‖
    étiquette ; données associées = les 32 octets du `sha256` de la pièce
    rédigée ; l'original est le JCS intégral de la valeur reçue (le texte
    UTF-8 d'une pièce texte, les octets d'un corps non JSON). Deux originaux
    qui donnent la même pièce rédigée (même nom de fichier) : le premier est
    gardé, jamais réécrit (`vault_original_kept`). CT-7 EX-3.11 ne dit pas
    comment les deux personnes sont authentifiées : `dechiffrer` reçoit les
    identités de l'outil d'exploitation, exige une approbation de la même
    pièce et du même motif par une autre personne de la liste autorisée,
    consigne chaque tentative (accordée ou refusée) hors du coffre et force
    la ligne sur disque avant de rendre l'original.
27. **EX-3.6 et la validation au rechargement.** `validerConfiguration` est
    synchrone (contrat du cœur) : le contrôle des jetons (EX-10.23
    opération 4) d'un rechargement s'exécute dans le fil qui l'appelle, borné
    par `redaction_budget_ms` par motif nommé ; toutes les autres opérations
    de la rédaction (pièces, motif d'une décision, valeurs en ligne, effets et
    leurs `extract`) passent par les fils de calcul. Le crochet synchrone
    `executerExtract` reste offert ; le cœur emploie `evaluerEffets`, qui
    évalue le gabarit entier dans un fil.
28. **Groupes imbriqués et noms en double** (EX-10.6 ne les borne pas). Le
    paquet `regexp` de Go refuse une imbrication au-delà de 1 000 ; ECMAScript
    (Node.js 22) refuse un nom de groupe en double. Lecture : les deux sont
    refusés ; un motif de 1 024 caractères au plus (schéma) n'atteint pas la
    première borne.
29. **Clé de pseudonymisation et EX-10.21.** Le contrôle « règles changées
    sans changer `redaction.name` » compare les documents, référence de la
    clé comprise, jamais sa valeur : une nouvelle valeur sous la même
    référence n'est pas vue (EX-10.13 (4) demande un nouveau `name`).
30. **Garde des fils de calcul.** Une opération qui ne rend pas la main
    (sérialisation démesurée) est arrêtée par `terminate()` après
    max(10 × `redaction_budget_ms`, 30 s) ; la pièce est alors la pièce non
    rédigeable `budget_redaction` dont `length` est celle que le fil a
    annoncée avant la rédaction (EX-8.7).

31. **Frontal MCP : utilisateur du pair d'une prise Unix** (EX-4.39 :
    « identifiant d'utilisateur du pair »). Node.js n'expose pas
    `SO_PEERCRED` sans module natif. Lecture : le démon envoie un défi
    aléatoire ; le connecteur crée en exclusion
    `<répertoire de mcp.socket>/.noortrace-defi-<défi>` (mode 0600) ; le
    démon lit son propriétaire (`lstat` : fichier ordinaire, un seul lien,
    contre un lien dur vers le fichier d'un autre), le supprime, puis cherche
    l'entrée `match.peer_user` du nom de ce compte (`/etc/passwd`). Le
    répertoire de la prise doit être inscriptible par les utilisateurs des
    connecteurs, avec le bit collant **exigé** depuis la relecture B
    (lecture 157).

32. **Frontal MCP : borne de `taille-depassee`.** Le vecteur fixe
    `limits.response_max_bytes = 512`, sous le minimum de 1024 de
    `$defs/bytes` du schéma de configuration. Lecture : le rejeu applique la
    borne du cas après la validation de la configuration ; le schéma n'est
    pas changé.

33. **Frontal MCP : `[<alias>] ` devant le message d'une elicitation**
    (EX-4.28) contre « le résultat intermédiaire est relayé tel quel »
    (EX-4.21) et le vecteur `input-required` (message rendu sans préfixe).
    Lecture : un `InputRequiredResult` de l'ère moderne est relayé tel quel ;
    le préfixe vise une requête `elicitation/create` de l'ère héritée, que la
    version 0 de ce lot ne relaie pas (`-32601`).

34. **Frontal MCP : `cacheScope`** (EX-4.14 : « si l'hôte est authentifié par
    un jeton porteur d'une identité »). Lecture : jeton statique ou OAuth ;
    l'utilisateur du pair d'une prise stdio n'est pas un jeton, et la valeur
    vient alors des serveurs de la page (`private` dans les vecteurs, rendu
    par le serveur `demo`).

35. **Frontal MCP : `serverInfo` d'une liste rendue à un hôte hérité.** EX-4.4
    (ère moderne) : « chaque résultat rendu porte serverInfo ». Les vecteurs
    `hote-herite-serveur-moderne` et `approbation-en-attente` rendent à un
    hôte hérité `tools/list` sans `_meta` et `tools/call` avec `serverInfo`.
    Lecture : `tools/list` d'un hôte hérité est `{"tools": […]}` (avec
    `nextCursor`) ; un résultat d'outil porte toujours `serverInfo` (pas 14).

36. **Frontal MCP : réponse au-delà de la borne sur un serveur stdio** (4.4
    pas 11 : « la connexion amont est fermée »). Fermer l'entrée d'un serveur
    stdio arrêterait aussi les appels des autres hôtes. Lecture : en stdio,
    l'appel finit par `-31013` à l'instant où la borne est atteinte et le
    reste de la ligne est lu sans être gardé (le vecteur ne montre aucune
    ligne de plus) ; en HTTP, la requête est fermée.

37. **Frontal MCP : `-31017` d'une lecture passante.** EX-4.46 et la ligne
    « Panne après relais » de 14.2 (« L : idem ») contre EX-14.6 et EX-14.8.
    Lecture : une lecture relayée en mode normal puis frappée d'une panne
    reçoit `-31017` ; une lecture relayée comme passante parce que le mode
    dégradé « stockage » était déjà actif au pas 7 reçoit sa réponse normale,
    son événement étant mis en attente.

38. **Frontal MCP : forme de `-32022` et de `server/discover`.** CT-2 renvoie à
    la page « Versioning and Compatibility » et à `server/discover` sans les
    citer. Lecture : `{"code":-32022,"message":"Unsupported protocol
    version","data":{"supported":[…],"requested":…}}` ; `server/discover`
    rend `resultType`, `supportedVersions`, `capabilities`, `serverInfo` et
    `_meta.serverInfo` ; `subscriptions/listen` part avec
    `{"toolsListChanged":true,"_meta":…}`.

39. **Frontal MCP : contraintes `x-mcp-header`** (EX-4.11 règle 4, renvoi à la
    page Streamable HTTP). Lecture : valeur chaîne au motif d'un jeton
    d'en-tête (1 à 64 caractères), sans doublon à la casse près, propriété de
    type primitif ; `Mcp-Param-*` vers le serveur : texte ASCII visible tel
    quel, sinon `=?base64?…?=`.

40. **Frontal MCP : identifiants amont des vecteurs.** 4.4 pas 9 : compteur
    « unique par connexion amont ». Les transcriptions portent des
    identifiants d'un même compteur d'un cas à l'autre (`e-000000000004` à
    `e-000000000019`). Lecture : le compteur est propre à chaque connexion ;
    le rejeu fixe sa valeur initiale d'après la première ligne `out`.

41. **Frontal MCP : ordre de `_meta` vers le serveur** (EX-4.7, pas 9). Lecture :
    les clés reçues gardent leur place, les trois clés
    `io.modelcontextprotocol/*` réécrites à la leur, les manquantes ajoutées
    à la fin dans l'ordre `protocolVersion`, `clientCapabilities`,
    `clientInfo` ; la sonde `server/discover` porte l'ordre du vecteur
    `hote-moderne-serveur-herite` (`protocolVersion`, `clientInfo`,
    `clientCapabilities`).

42. **Frontal MCP : `data` des erreurs de lecture** (4.4 pas 1). Seul
    `cr_dans_la_ligne` est nommé. Lecture : `-32700` porte `data.reason`
    parmi `json_invalide`, `utf8`, `bom`, `cle_double`, `substitut_isole`,
    `profondeur`, `membres`, `cadrage_non_admis` ; `-32602` porte
    `meta_requis`, `arguments_non_objet` ou `curseur_invalide` ; `Unknown
    tool` reste sans `data` (forme de la page Tools).

Lectures du lot « moteur de politique » (§7.5, 14.2, 14.6 ; CT-3 §11, §12) :

43. **Raison d'`observation_would_block`** (EX-14.16, EX-17.8 : « chaque appel
    qu'un mode bloquant aurait bloqué, retenu ou refusé »). La colonne
    `reason` de 17.2 n'a pas de valeur « retenu ». Lecture : sortie
    `a_approuver` → `approbation` (retenue et signal) ; `refuse` →
    `politique` ; `inconnu` (service indisponible) → `approbation` pour une
    écriture ou un outil susceptible, rien pour une lecture que 14.2 laisse
    passer ; une panne → sa raison de 14.2 ; budget → `redaction` ; quota →
    `quota`. Une ligne par raison et par appel, écrite après le scellement
    (`seq`) ou la mise en attente (`seq: null`) ; `would` est la décision
    évaluée, ou `quota` pour un quota refusé avant l'évaluation.
44. **Délai d'`evaluer`** (EX-7.4 : « le service répond dans
    `policy.timeout_ms` »). Le canal HTTP borne déjà chaque requête ; un
    service joint autrement (en mémoire, tests) pourrait ne jamais répondre.
    Lecture : le cœur borne l'attente lui-même ; au-delà, erreur
    `indisponible`, traitée par 14.2.
45. **Réponse vide immédiate à `decisions`** (EX-7.19 : « la relance dès
    qu'elle répond »). Un service qui ne tient pas l'attente longue ferait
    tourner la boucle à vide. Lecture : une réponse vide rendue en moins de
    100 ms est relancée après 100 ms ; toute autre réponse est relancée
    aussitôt. Sans réponse au terme de `wait_ms + timeout_ms`, le service est
    indisponible (consigné une fois) et la requête est réessayée après 200 ms,
    puis un délai doublé jusqu'à 5 s.
46. **« Ticket ouvert » d'EX-15.8.** Lecture : une ligne `retenue` des
    fichiers des approbations dont l'événement est dans la chaîne (son `hash`
    y figure, 12.9) et dont le ticket n'a pas de décision scellée. Au
    démarrage, le refus vaut quel que soit le mode de la version annoncée
    avant l'arrêt (le même cas « est une erreur de validation », code 2) ; au
    rechargement, seulement depuis un autre mode.
47. **`noortrace_observation_marks_total`** (« événements scellés avec une
    marque »). Lecture : compté au relais de l'appel marqué, que l'événement
    soit scellé aussitôt ou mis en attente (il porte la même marque) ; un
    événement perdu au-delà des bornes n'est pas compté.
48. **Annulation d'une requête retenue** (EX-4.50 : « si elle a pris fin
    (délai, annulation par l'hôte) » ; EX-4.23 : `-31012` « seulement si l'hôte
    attend encore »). Lecture : `notifications/cancelled` d'une requête
    retenue met fin à la rétention sans réponse (l'hôte n'attend plus) ; le
    ticket continue, et la première ré-émission reconnue qui suit est retenue.
    Une fermeture de la connexion de l'hôte n'est pas une annulation : la
    rétention finit à `hold_timeout_ms`.
49. **Pièces d'une ré-émission retenue.** Une ré-émission `en_attente`
    n'écrit pas de pièce (aucun événement, CT-3 EX-7.19) ; retenue en mode
    `retenir`, elle finit par un relais ou un `refusee` qui citent sa pièce
    « arguments » et ses pièces de contexte. Lecture : elle les écrit avant
    d'être retenue (la pièce « arguments » est celle de la `retenue`, RL-2).
50. **Bail en mode observation** (EX-14.16 : « `bail` quand l'instance a été
    active » ; EX-14.17 : `-31010` `bail_non_detenu` rendu par une instance
    passive). Lecture : un bail perdu après avoir été détenu (raison `bail`)
    laisse passer l'appel, événement en attente ; une instance qui n'a jamais
    détenu le bail rend `bail_non_detenu`.
51. **Avertissements d'EX-4.14 de CT-3** (« leur texte n'est pas fixé »).
    Lecture : codes `pointeur_redige`, `liste_exclusion`,
    `fenetre_plusieurs_outils`, `fenetre_sans_same_arguments`,
    `fenetre_sans_condition`, `demandeur_sans_identite`, sous le pointeur du
    membre ; un chemin rédigé est celui d'une règle de rédaction à détecteur
    `champ` et `path` de portée `arguments`, comparé préfixe pour préfixe à
    `/arguments<path>`. Les avertissements ne sont calculés que pour un
    document sans erreur.
52. **Substitut isolé dans une clé** (EX-4.2 point 4 : « toute chaîne du
    document »). Lecture : clés et valeurs ; l'erreur porte le pointeur du
    membre. Dans la configuration, le JSON strict du pas 1 refuse déjà un
    substitut isolé : le point 4 ne s'atteint que par la validation du
    document seul.
53. **Quota en mode observation pour une autre méthode que `tools/call`**
    (EX-14.17 : jamais `-31013` de direction `quota`). Lecture : aucune
    méthode n'est refusée pour un quota en mode observation ; la ligne
    `observation_would_block` est écrite quand même, `would: "quota"`.
54. **Politique de `journal-demo` et validation** (B.6, CT-3 4.1 : `rules`
    y est un tableau illustratif « opaque pour CT-2 »). Lecture : le rejeu de
    seq 5 à 7 démarre le cœur sur cet ensemble sans le valider (un démon le
    refuserait au pas 3), le service simulé décidant lui-même.
Lectures du lot « frontal modèle » (§5) :

55. **Corps des refus `401` et `415` hors Gemini.** EX-5.7 point 1 et EX-5.8
    disent le statut sans fixer de corps (EX-5.30 ne le fait que pour
    Gemini). Lecture : la forme du fournisseur, le message du tableau
    d'EX-5.30 ; Messages : `{"type":"error","error":{"type":"authentication_error"
    ou "invalid_request_error","message":…}}` ; Chat Completions et Responses :
    `{"error":{"message":…,"type":"invalid_request_error","param":null,"code":"noortrace_hote_inconnu"
    ou "noortrace_requete_comprimee"}}`.
56. **Corps du `504` hors Gemini** (EX-5.24 ne donne qu'un corps, de la forme
    de Messages, « sur une route gemini, le corps 504 d'EX-5.30 »). Lecture :
    ce corps pour toute route qui n'est pas `gemini`, Chat Completions et
    Responses compris.
57. **Refus sans route** (EX-5.2 : `400` d'une normalisation ; EX-5.26 :
    `400` d'un cadrage). Aucun format n'est encore connu. Lecture : `400` sans
    corps ; de même pour un en-tête d'authentification, de cadrage ou de
    délégation reçu deux fois (non nommé par CT-2 : la passerelle ne choisit
    pas entre deux valeurs) ; `model_request_refused` porte alors les raisons
    `chemin`, `cadrage` ou `entete_double`, ajoutées à celles d'EX-17.2.
58. **Coupure avant le premier octet** (EX-5.24 et table de 5.3.3 :
    « connexion au fournisseur impossible ou délai de connexion », « délai du
    premier octet »). Une connexion refusée ou fermée avant la réponse n'est
    pas un délai. Lecture : connexion impossible → phase `connexion`
    (`timeout_ms` = `connect_timeout_ms`) ; fermée après l'envoi, avant les
    en-têtes → phase `premier_octet` (`first_byte_timeout_ms`) ; `504` dans
    les deux cas, rien n'ayant été relayé.
59. **Inactivité d'un corps hors flux** (EX-5.24 : « silence entre deux
    octets d'un flux »). Lecture : la borne vaut pour tout corps ; hors flux,
    la pièce est l'objet `noortrace_http_error` de statut `504` et de phase
    `inactivite` ; en flux, la forme consolidée incomplète.
60. **« Flux clos vers l'hôte »** (EX-5.13, EX-5.24, table de 5.3.3). Lecture :
    après une coupure amont, un délai d'inactivité ou la borne d'un corps, la
    connexion de l'hôte est fermée sans fin de corps régulière, pour qu'un
    SDK ne prenne pas une réponse tronquée pour complète.
61. **L'hôte ferme avant toute réponse** (EX-5.13 : « donne la même marque » ;
    il n'y a pas de forme où la poser). Lecture : la pièce « réponse » est le
    corps reçu, vide (`application/octet-stream`, 0 octet), `is_error: true`,
    échange incomplet, `host_disconnected`.
62. **« Requête suivante de la même connexion d'hôte »** (5.3.1 pas 8).
    Lecture : la connexion HTTP (prise TCP) ; la requête suivante sur la même
    prise attend la durabilité de l'échange précédent ; des requêtes
    parallèles d'un même hôte sur d'autres prises ne s'attendent pas.
63. **`Content-Encoding` d'une réponse comprimée** (EX-5.9 : « relayée
    comprimée à l'hôte » ; table de 5.3 qui ne nomme pas l'en-tête). Lecture :
    il est rendu à l'hôte avec le corps comprimé, faute de quoi l'hôte ne
    pourrait pas le lire.
64. **Statut amont 1xx ou 3xx** (5.3.1 pas 7 ne nomme que `2xx` et `≥ 400`).
    Lecture : traité comme un statut d'erreur (objet `noortrace_http_error`,
    `is_error: true`) : la réponse n'est pas exploitable (CT-1 §5.3).
65. **Intention vide.** 5.5 dit « texte vide → `null` » pour Gemini seulement.
    Lecture : de même pour les autres formats ; et le texte qui précède un
    appel (5.6) joint les blocs `text` (Anthropic) et les `output_text`
    (Responses) par `\n`, comme la table de 5.5.
66. **Événements après l'événement terminal** (`message_stop`, `[DONE]`,
    `response.completed`, `failed`, `incomplete`). Lecture : ignorés et
    comptés ; la forme close est celle qui a été inscrite au registre.
67. **Prompt nommé** (EX-8.6 : la pièce est `[PROMPT:<nom>]`). Lecture : pièce
    `text/plain` `redacted: true` (elle remplace le texte reçu) ; sans nom de
    la connexion ni nom déclaré admis, la pièce est le texte rédigé (le
    défaut). Un nom déclaré refusé est consigné `delegation_refused`, champ
    `prompt_version`.
68. **Passthrough d'une route Gemini** (EX-5.29 ne vise que les deux couples
    servis). Lecture : la chaîne de requête est relayée telle quelle, sauf un
    paramètre `key`, refusé (`cle_dans_url`) pour la même raison.
69. **EX-3.6 et le frontal modèle.** L'analyse SSE est incrémentale, bornée
    par `json_max_depth` et `json_max_members` par événement, et doit
    précéder l'écriture de chaque fragment vers l'hôte (5.6) : elle se fait
    dans le fil d'entrée-sortie, comme l'analyse d'un corps hors flux dans sa
    borne ; la rédaction et la sérialisation des pièces, elles, passent par
    les fils de calcul du rédacteur.

Lectures du lot « moteur de politique » (reprise) :

70. **Intention par référence dans `evaluer`** (EX-7.4 : « l'objet `{ …,
    "intent", … }` (`$defs/requete_evaluer` de `ticket-v0`) », dont `intent`
    est une chaîne d'au plus 4 096 caractères ou `null` ; 7.2 et EX-5.21 :
    l'intention corrélée est une chaîne ou une référence de pièce
    `text/plain`). Une référence telle quelle est refusée par le service
    (`requete_invalide`), donc traitée comme une indisponibilité. Lecture : le
    membre `intent` porte le texte de la pièce, déjà rédigé (c'est la
    requête du cas CT-3 `console/modeles/intention-par-reference`, dont
    l'événement retenu porte la référence et la requête le texte, que la
    console affiche « non vérifiable », EX-9.15) ; au-delà de 4 096
    caractères, ou pièce absente ou illisible, `null`, consigné
    (`intent_not_sent`, sans la valeur). L'événement garde la référence.
71. **Sortie du mode dégradé « horloge »** (EX-7.9 : « jusqu'à ce que
    l'horloge murale ait rejoint `ts` précédent » ; EX-7.13 : « en sort quand
    l'horloge murale est revenue dans la tolérance de l'avance monotone » ;
    EX-14.11). Le contrôleur ne constatait la sortie qu'en fixant le `ts`
    d'un nouvel événement, alors qu'en mode bloquant aucun événement ne peut
    plus être scellé (appels bloqués, remises acquittées `temporaire`,
    expirations différées) : le mode ne se levait jamais. Lecture : la sortie
    est constatée au tic, aux mêmes conditions.

Lectures du lot « frontal modèle » (§5), modes ICAP et miroir, jeton OAuth,
quotas et TLS :

72. **Jeton OAuth de la passerelle** (EX-5.8 point 2 : « `oauth_subject` :
    jeton OAuth dont l'audience est l'URI de la passerelle, dans
    `X-Noortrace-Token` (et dans `Authorization` en mode `propre`) »). CT-2
    prévoit cette connexion d'hôte ; elle est servie. Ni le serveur
    d'autorisation, ni les clés, ni les portées ne sont nommés pour
    `model` : le schéma n'a pas de membre `model.oauth`. Lecture : le jeton
    est vérifié comme celui du frontal MCP, par `mcp.http.oauth`
    (`authorization_servers` pour l'émetteur, `jwks_uri`, `required_scopes`,
    expiration, signature), l'audience attendue étant l'URI de la passerelle,
    `http://<model.listen>`, ou `https://` avec `model.tls`. Une entrée
    `oauth_subject` sans `mcp.http.oauth` est une erreur de configuration
    (`config_invalid`, `/model/hosts/<i>/match/oauth_subject`, code 2 au
    démarrage, EX-15.4 pas 3), comme une entrée `oauth_subject` hors du mode
    `passerelle`. Un jeton refusé donne `401` sans relais, consigné
    `auth_failed` (raison `oauth_<cause>`).
73. **Quotas d'EX-4.47 sur `model.hosts`** (EX-4.47 : « Chaque entrée de
    connexion d'hôte porte, toutes requises par le schéma, … ; au-delà, la
    requête est refusée au pas 1 par `-31013` » ; 14.2, ligne « Mémoire » :
    « `-31013` pour une taille de message dépassée ou un quota (EX-4.47) »
    en colonnes E et L, « bloquant (`503`) » en colonne M). `-31013` est un
    code JSON-RPC, que le frontal modèle n'a pas. Lecture : les quatre quotas
    s'appliquent aux entrées de `model.hosts` ; un quota atteint bloque
    l'échange par `503` avec le corps d'un échange bloqué (14.2 : « reçoit
    `503` avec le corps d'erreur du format de la route » ; EX-5.30 pour
    Gemini), sans relais ni pièce, consigné `call_blocked` (`reason: "quota"`,
    `class: "modele"`, `limit_requests`, `limit_bytes` ou `limit_ms`), en
    passerelle et en REQMOD (EX-14.12 : « la colonne M s'applique en
    REQMOD ») ; jamais en miroir (EX-5.6 : « Rien n'est bloqué ») ; en mode
    observation, `observation_would_block` (EX-14.16). Les octets reçus sont
    comptés pour toute requête lue, refusée comprise ; le temps de capture
    d'une requête (analyse JSON, rédaction, sérialisation des pièces) compte
    pour les requêtes suivantes, ajouté après le contrôle de son propre
    quota ; un couple `passthrough` ne compte que les octets reçus.
74. **Version de TLS de `model.tls` et d'ICAPS** (EX-5.2 : « TLS par le client
    ou par un mandataire inverse devant le démon » ; EX-5.3 : « ICAPS »).
    CT-2 ne fixe pas de version. Lecture : plancher TLS 1.2, celui de Node.js
    par défaut, écrit explicitement (`minVersion`) pour qu'un changement de
    défaut ne l'abaisse pas ; un certificat ou une clé illisible empêche le
    démarrage (`demarrage_refuse : frontal_modele`, code 2).
75. **ICAP : requête hors des échanges capturés** (EX-5.4 ne vise que les
    routes ; EX-5.2 : « Tout autre couple (méthode, chemin) reçoit `404` sans
    relais » vaut pour la passerelle, qui sert elle-même la requête). Le
    mandataire, lui, relaie ce qu'il veut, et EX-5.4 interdit `204`. Lecture :
    une requête dont le couple (méthode, chemin) n'est pas une route
    d'échange (`passthrough` compris) est rendue modifiée (`200`) sans en-tête
    `X-Noortrace-*` et sans identifiant, consignée `model_route_not_found`
    (`mode: "icap"`), sans pièce ni événement ; sa réponse, en RESPMOD, est
    rendue inchangée, consignée `icap_respmod_non_capture` (de même pour une
    réponse dont la requête encapsulée est absente, ou d'hôte inconnu).
76. **Blocages en REQMOD au-delà des « deux cas seulement »** (EX-5.4 :
    « une requête refusée par EX-5.7 … et un mode dégradé bloquant pour les
    échanges de modèle (14.2) »). D'autres règles refusent « une requête »
    sans viser la seule passerelle : EX-5.8 (« sinon bloquée en REQMOD
    (ICAP) »), EX-5.29 (chaîne de requête Gemini, « refusé par `400` … sans
    relais »), EX-5.32 (serveurs MCP et contenu en cache déclarés au
    fournisseur, `refuser` par défaut), EX-5.33 (« Bornes de taille (tous
    formats) ») et le quota (lecture 73). Lecture : en REQMOD, ces refus
    donnent eux aussi une réponse HTTP encapsulée au statut et au corps de
    leur règle, sans événement, consignée (`model_request_refused`,
    `mode: "icap"`) ; relayer une requête que le texte interdit de relayer
    (clé dans l'URL, serveurs MCP joints par le fournisseur hors du pare-feu)
    serait l'écart. La requête admise est rendue avec sa cible d'origine
    (`?alt=json` compris). En miroir, rien n'étant bloqué, les déclarations
    d'EX-5.32 sont consignées (`provider_mcp_bypass`,
    `provider_cache_reference`, `mode: "miroir"`) et l'échange donne son
    événement.
77. **ICAP : REQMOD sans RESPMOD** (EX-5.4 : la requête « modifiée » part
    vers le fournisseur ; aucun délai n'est nommé pour la suite). Lecture :
    si aucun RESPMOD n'est retrouvé dans `first_byte_timeout_ms` après le
    REQMOD, l'échange est scellé `is_error: true` avec la pièce
    `noortrace_timeout` de phase `premier_octet` (EX-5.24), comme une
    réponse jamais reçue en passerelle (table de 5.3.3) : la requête a pu
    atteindre le fournisseur ; un RESPMOD qui arrive ensuite ne retrouve plus
    cet échange et donne celui à pièce « requête »
    `{"noortrace_requete_inconnue": true}` d'EX-5.4.
78. **Miroir : protocole de la prise du démon** (EX-5.6 : « les remet au démon
    par la prise locale, sous la forme d'un couple (requête, réponse)
    horodaté, avec l'adresse source du flux » ; la forme n'est pas fixée).
    Lecture : une ligne JSON par couple, `{ "version": 0, "source",
    "t_requete", "t_reponse", "request": { "method", "target", "headers",
    "body" (base64) }, "response": { "status", "headers", "body",
    "body_length", "complete" } | null }`, et une ligne de réponse par
    couple (`{ "ok": true, "seq", "pending_id" }` ou `{ "ok": false,
    "reason" }`) ; ligne bornée à
    `⌈(model_request_max_bytes + model_response_max_bytes) × 4/3⌉ + 65 536`
    octets, au-delà la connexion est fermée (`mirror_line_refused`) ; prise
    créée en mode `0660`. `duration_ms` est `t_reponse − t_requete`.
79. **Miroir : entrée de l'adaptateur de capture** (EX-5.6 : « reçoit la copie
    déchiffrée fournie par l'équipement du client » ; le format de chaque
    équipement est hors de la version 0). Lecture : l'adaptateur
    `bin/noortrace-miroir` reçoit sur une prise TCP des trames — une ligne
    JSON `{ "connexion", "sens": "client" | "serveur" | "fin", "source",
    "longueur" }` suivie de `longueur` octets — et réassemble chaque sens en
    HTTP/1.1 (`Content-Length`, `chunked`, corps jusqu'à la fermeture,
    réponses `1xx` ignorées, `HEAD` sans corps) ; l'intégration d'un
    équipement réel est un traducteur vers ces trames.
80. **Miroir : couples sans événement et couples sans réponse** (EX-5.6 :
    « Le démon construit l'événement comme en passerelle » ; EX-5.7 : un
    corps non analysable « ne peut pas être rédigé »). Lecture : un couple
    dont la requête serait refusée par EX-5.7 ou EX-5.33, d'hôte inconnu
    sans entrée `"inconnu"` (EX-5.8 : « consignée sans événement
    (miroir) ») ou hors des routes ne donne pas d'événement et est consigné ;
    un couple sans réponse dans la copie (connexion close avant) donne un
    échange `is_error: true` dont la réponse est vide, comme une fermeture
    par l'hôte (lecture 61).
81. **Adresse d'un support S3** (EX-12.39 : « Cible : chemin et requête
    relatifs au service, sans hôte » ; 15.1 : `endpoint` « Origine HTTPS
    seule, sans chemin », `null` pour Amazon S3). Lecture : la cible
    d'EX-12.39 est envoyée telle quelle ; sans `endpoint`, à
    `https://<bucket>.s3[.<region>].amazonaws.com` (style « virtual-hosted ») ;
    avec `endpoint` (service compatible), au chemin `/<bucket><cible>` de
    cette origine (style « path », servi par tous les services compatibles
    sans DNS propre) ; `region` nulle : `us-east-1`. La signature SigV4
    (laissée à la couche d'accès, EX-12.39, section 21) porte sur le chemin
    réellement envoyé.
82. **Format des identifiants d'un support** (EX-12.36 : « son contenu suit
    le format d'identifiants du support »). Lecture : S3, objet JSON
    `{ "access_key_id", "secret_access_key", "session_token"? }` ; Azure et
    GCS, `{ "bearer_token" }`, un jeton porteur déjà obtenu (Entra ID,
    OAuth 2.0), son obtention étant laissée aux outils du support (section
    21 : « la signature des requêtes (SigV4, clé partagée, OAuth), laissée aux
    bibliothèques des supports »).
83. **Essais d'une requête** (EX-12.40 : « trois essais de la même requête,
    après 1 s, 2 s puis 4 s » ; EX-12.16 : « `409 Conflict` à réessayer »).
    Lecture : l'essai initial puis trois nouveaux essais, après 1 s, 2 s et
    4 s, pour un support injoignable, un délai de 10 s dépassé, `500`,
    `502`, `503`, `504` ; à la copie de l'écrivain, `409` aussi ; `403`,
    `404`, `412` et les autres statuts ne sont pas réessayés. Une copie
    encore en échec est reprise par le balayage de la supervision.
84. **Azure et Google Cloud Storage : ce que le texte ne fixe pas** (12.6 :
    les en-têtes de la réponse à l'écriture « n'ont pas été relus pour
    cette révision et sont fixés en phase 2 (section 21) » ; EX-12.35 : la
    liste des versions de ces supports « n'a pas été relue » ; EX-12.30 et
    section 21 : la copie GCS passe en version 1). Lecture : seules les
    requêtes qu'EX-12.39 fixe sont mises en œuvre pour ces supports (gel
    d'une version, lecture de son état) ; la copie, la liste des versions,
    la lecture et l'écriture d'un objet (registre des gels) lèvent
    `ErreurNonFixe` au lieu d'inventer une requête : l'écrivain consigne
    `worm_copy_failed`, et l'outil de gel s'arrête avant toute requête de
    gel (code 4, `operation_non_fixee`). Le gel n'est donc utilisable de
    bout en bout que sur `s3-object-lock` en version 0 de ce paquet.
85. **Copie qui reçoit `412`** (EX-12.16 : « `412 Precondition Failed` si un
    autre écrivain a gagné »). Un `412` vient aussi d'une copie antérieure
    de la même instance dont la réponse a été perdue. Lecture : la version
    courante est relue (SHA-256 au fil de l'eau) ; identique au fichier
    local, la copie est tenue pour faite avec cette version et `copied_at`
    = son `Last-Modified` ; différente, rien n'est réécrit et
    `worm_copy_failed` est consigné en erreur (`objet_present_different`).
86. **Version absente de la réponse à la copie** (EX-12.29 : `version_id`
    « ou `null` s'il n'en rend pas » ; EX-12.33 : « `HEAD` avec
    `versionId` »). Lecture : le contrôle lit alors la version courante
    (`HEAD` sans `versionId`).
87. **Échéance attendue au relevé d'une version sans ligne au registre**
    (EX-12.33 compare à `copied_at` ; EX-17.6 pas 3 : la version « est
    inscrite »). Lecture : `copied_at` est la date `LastModified` de la
    liste des versions (date de création que le support emploie) ; la ligne
    inscrite porte le SHA-256 et la longueur relus sur le support et cette
    date, au registre de l'époque courante (démon) ou de la plus grande
    époque présente (`noortrace-ctl worm releve`).
88. **Gel attendu avec `legal_hold_on_write`** (EX-17.6 pas 2 : « pour toute
    version avec `legal_hold_on_write` »). Lecture : les copies de
    l'écrivain seulement (sous-préfixes de EX-12.32) ; les enregistrements
    du registre des gels, écrits par les gardiens sans gel, n'en attendent
    pas.
89. **Cadence du relevé** (EX-17.6 : « Tous les `lock_audit_interval_days`
    jours » ; EX-12.1 : aucun fichier d'état mutable). Lecture : l'instant du
    dernier relevé n'est pas gardé ; un relevé est fait au premier tour de
    la supervision après le démarrage, puis tous les
    `lock_audit_interval_days` jours ; `noortrace_worm_last_audit_age_s`
    en part.
90. **`noortrace-ctl worm releve`** (EX-17.6 : « à la demande
    (`noortrace-ctl worm releve`, consignée), le fil de supervision » ;
    EX-18.1 : `noortrace-ctl` local, sous l'utilisateur du démon ; aucun
    canal entre l'outil et le démon n'est fixé). Lecture : la commande
    exécute le même relevé, avec la configuration du démon et les
    identifiants de l'écrivain, dont elle n'emploie que les droits de
    lecture ; ses lignes vont au journal d'exploitation
    (`supervision.ops_log.path`, ou `--journal-exploitation`) ; sortie : la
    synthèse JSON ; codes 0 (conforme), 1 (non-conformité ou version
    inattendue), 2, 4 (relevé impossible).
91. **Manifeste à plusieurs versions** (EX-12.35 pas 2 : « lire chaque
    version […] et en prendre `first_seq` et `last_seq` »). Lecture : la
    première version lisible dans l'ordre de la liste des versions ; toutes
    les versions sont gelées (pas 5, `versions_multiples`).
92. **Références prises au périmètre et par `copy_pieces`** (EX-12.35 pas 4 :
    « toute référence `{ sha256, length, redacted }` de l'événement,
    `code.prompt_version`, et `policy_sha256` d'un événement de
    politique »). Lecture : une référence en ligne (avec `value`, CT-1 §5.4)
    n'a pas de pièce stockée et n'est pas prise ; `policy_sha256` est lu dans
    la valeur en ligne des arguments de l'événement de politique.
93. **Fichiers d'ancres** (EX-12.27 : « le répertoire `ancres/` que CT-5 écrit
    est copié de la même façon »). Lecture : chaque fichier présent sous
    `ancres/` est copié une fois, sous sa clé, par le balayage horaire ; un
    fichier modifié après sa copie n'est pas recopié (même clé, `412`,
    `objet_present_different`). Complément du lot F2 du composant (qui écrit
    désormais `ancres/` sous le répertoire du journal, CT-5 EX-5.14 et
    EX-12.1) : un fichier n'est copié qu'une fois fermé, pour ne jamais
    copier un état intermédiaire. Les pièces (`rfc3161/*.tsq|.tsr|.der|.crl.pem`,
    `ots/*.ots|.nonce`, `entetes-bitcoin.json`) le sont dès leur écriture ;
    `acquisitions.ndjson`, en ajout seul, quand le manifeste de la période
    existe et que la T-10 différée de chaque jeton promu est décidée (ou que
    `rfc3161.crl_capture.enabled` est faux, lu dans le document d'ancrage
    du composant branché) ; la file `file-<epoque>.ndjson`, quand son époque
    est inférieure à celle de l'écrivain ; `registre/` suit la même règle
    des fichiers fermés. `queue.path` est à placer sous le répertoire du
    journal (`<journal>/ancres/file`) pour être dans le périmètre.
94. **Moment de la copie des pièces** (EX-12.16 : « les pièces, sont copiés
    vers le support après fermeture »). Lecture : à la copie du segment qui
    les référence, puis par le balayage pour celles qui manquent.
95. **« Dernière » demande de levée** (EX-12.38, `demande_inconnue` :
    « l'empreinte de la **dernière** `demande_levee` du gel »). Lecture : la
    dernière `demande_levee` qui précède la `levee` dans la suite ; les
    vecteurs `demande-remplacee` et `levee-en-double` y concordent.
96. **Gel actif et « dernier enregistrement valide »** (EX-17.7). Lecture :
    le dernier enregistrement du plus long préfixe sans erreur de garde ;
    une `levee` qui viole la garde laisse le gel actif, ses versions
    attendues `on`.
97. **Levée constatée sur Azure** (EX-12.40 pas 5 : relire et exiger
    l'état attendu ; EX-12.33 : `x-ms-legal-hold` absent → `jamais`, « This
    header isn't returned if there's no legal hold on the blob », R13-F19).
    Lecture : à la levée, `jamais` vaut `off`.
98. **Arrêt sur `403` ou `501` à la première requête de gel** (table
    d'EX-12.40 : « arrêt, rien n'a été gelé », code 4), alors que
    l'enregistrement `pose` est déjà écrit (pas 4). Lecture : aucun
    `pose_resultat` n'est écrit ; `reprendre` complète la pose une fois le
    droit accordé.
99. **Code de sortie d'`etat`** (EX-12.36 : `etat` « imprime, ne rien
    écrire »). Lecture : 0 si la garde est respectée et chaque version attendue
    `on` l'est ; 1 sinon (contre-vérification quotidienne du rôle Lecteur,
    EX-17.7) ; 4 si le support est injoignable.
100. **Enregistrement déjà présent en demande ou en levée** (table
     d'EX-12.40 : « relire le registre, recommencer la vérification de la
     garde, ne rien envoyer »). Lecture : un nouvel essai, après relecture et
     garde ; un second `412` rend le code 3 (`chaine_rompue`).
101. **Liste des objets d'un gel illisible ou d'empreinte différente** à la
     levée, à la reprise ou à l'état (EX-12.37 : `objects` identique dans tous
     les enregistrements). Lecture : code 3, `objets_differents`, sans
     requête.
102. **Instant `t_renew`** (EX-13.3 : « l'instant monotone du dernier
     renouvellement réussi », « un renouvellement n'est tenu pour réussi qu'à
     la réception de la réponse »). Lecture : l'instant monotone d'ENVOI de
     la demande qui a réussi (le magasin a compté son TTL après cet envoi) :
     la borne la plus prudente.
103. **`acquire_wait_ms`** (EX-13.3 : « attente avant d'abandonner
     l'acquisition au démarrage » ; 13.4 pas 1 : B « réessaie toutes les
     `lease.renew_ms` » tant que A renouvelle). Lecture : `acquire_wait_ms`
     borne les essais tant que le magasin est injoignable (puis démarrage
     refusé, raison `bail`) ; un bail détenu par une autre instance donne
     l'instance passive, qui réessaie toutes les `renew_ms` sans limite.
104. **Instance passive et frontaux** (13.4 pas 1 : B « répond aux hôtes qui
     la joindraient `-31010` » ; pas 7 : « B accepte les connexions
     d'hôtes »). Lecture : les frontaux s'ouvrent pendant l'attente et
     rendent `-31010 bail_non_detenu` (14.2) ; le pas 7 est le service
     normal, ouvert seulement après la prise du bail ET la fin de la reprise
     (intentions, attente, événement de politique, EX-9.8 : un appel admis
     plus tôt aurait son intention reprise à tort) ; `/healthz` rend
     `standby` et `/readyz` `503` jusque-là.
105. **Bail perdu, puis reprise** (EX-13.6 : « Il ne reprend qu'après une
     nouvelle acquisition » ; 13.4 pas 8 : « A redevient passive et relit le
     journal avant toute nouvelle acquisition »). Lecture : le démon reste
     en mode dégradé « bail » (bloquant), puis se relance dans le même
     processus (frontaux et cœur arrêtés, démarrage complet) : il redevient
     passif tant qu'une autre instance détient le bail, et relit le journal
     (EX-12.10) après sa prochaine acquisition, comme tout démarrage.
106. **Magasin `postgresql` : table, ligne, durée** (13.2 donne la table et
     l'`UPDATE`, sans la création de la ligne du journal). Lecture : `CREATE
     TABLE IF NOT EXISTS` aux colonnes de 13.2 (`epoch` à 0 par défaut) et
     `INSERT … ON CONFLICT (name) DO NOTHING` de la ligne (`holder` et
     `expires_at` nuls, `epoch` 0) avant l'`UPDATE` d'acquisition, qui rend
     donc 1 la première fois ; `$ttl` = `ttl_ms` × `interval '1
     millisecond'` ; à l'arrêt propre, `holder` est remis à nul (par détenteur
     et époque) pour qu'une autre instance prenne le bail sans attendre le
     TTL ; DSN en forme URI `postgresql://`, `sslmode` `disable`, `require`,
     `verify-ca` ou `verify-full`, lu sans retrait de fin de ligne (15.2).
107. **Magasin `etcd`** (13.2 nomme les appels gRPC `LeaseGrant`, `Txn`,
     `LeaseKeepAlive`). Lecture : la passerelle JSON de la même API
     (`POST /v3/lease/grant`, `/v3/kv/txn`, `/v3/lease/keepalive`,
     `/v3/lease/revoke`) ; TTL arrondi à la seconde supérieure ; la
     transaction de renouvellement et de vérification compare la
     `mod_revision` de la clé à l'époque et sa valeur à l'instance ; un
     `LeaseRevoke` à l'arrêt propre.
108. **Clôture par le stockage** (EX-13.10 (1) : le repreneur rend le
     stockage du prédécesseur inaccessible « par un détachement forcé du
     volume […] ou par une réservation persistante SCSI ou NVMe » ; (3) : il
     « consigne la taille finale »). Lecture : le démon n'a ni le droit ni le
     moyen de détacher un volume : le moyen nommé par `lease.fencing` est
     exécuté par l'orchestrateur (CT-8, EX-10.17), et le démon le recopie
     dans `lease_acquired` ; les tailles sont consignées après la relecture
     et sa troncature éventuelle (ligne `lease_predecessor_files`, nom que la
     spécification ne fixe pas), et toute croissance ultérieure donne
     `journal_fork`, contrôlée au tic (toutes les 10 s au plus).
109. **Clé du MAC de relais différente** (13.4 pas 1 : « une différence est
     une erreur de configuration (`relay_mac_key_mismatch`), et `B` ne prend
     pas le bail » ; CT-8 EX-10.17 : « la passive est `standby` sans la
     ligne » une fois corrigée). Lecture : pour tout magasin, avant toute
     acquisition, sans rien tronquer (le bail n'est pas détenu) ; le démon
     reste passif et ne prend pas le bail ; sans attente (cœur seul), le
     démarrage est refusé, code 2. L'avertissement `relay_mac_key_changed`
     du cœur ne peut plus se produire.
110. **Alerte « Gel non posé sur une version d'un gel actif »** (17.4 ;
     EX-17.7 ne nomme pas la ligne). Lecture : `worm_lock_check`, niveau
     `error`, `when: "registre_gels"`, raison `gel_absent` (ou
     `gel_illisible`), avec le `gel_id`.

Lectures du lot « SDK et OpenTelemetry » (§6) :

111. **Classe configurée d'un outil du SDK** (table de 6.2 : « celle de la
     configuration du démon prime ; une classe déclarée ne peut que la
     renforcer » ; EX-6.15, EX-6.18 ; `sdk_class_override_refused`, EX-17.2).
     Le schéma `configuration-enregistreur-v0` n'a aucun réglage de classe
     pour un outil du SDK : une classe ne se règle que par
     `$defs/tool_settings/class` et `$defs/tool_server/class_default`, sous
     `policy.servers.<alias>` (`$defs/policy_set/servers`, carte des
     serveurs d'outils), et par `$defs/otel_tool_settings` pour une source
     OpenTelemetry ; `$defs/host_connection` (entrées de `sdk.hosts`) n'a
     pas de membre de classe ni `tools`, `$defs/sdk_policy` n'a que
     `aliases`, et l'alias du SDK est distinct de tout alias de serveur
     (EX-6.6, EX-15.4). Lecture : en version 0,
     aucune classe n'est configurée ; la classe déclarée s'applique, à
     défaut `ecriture` ; la règle de renforcement (`classeSdk`) est écrite et
     éprouvée seule, et `sdk_class_override_refused` ne peut être consigné
     qu'une fois qu'une révision aura donné ce réglage.
112. **Identité du pair sur la prise du SDK** (EX-6.1 : « identité du
     processus pair (prise Unix) » ; EX-6.10 : le SDK « n'y reçoit jamais de
     requête du démon »). Lecture : la preuve de la lecture 31 (défi,
     fichier créé en exclusion, propriétaire relu), puis la ligne
     `{"noortrace_identite":"acceptee"}`, aussi après le jeton d'une prise
     TCP ; ces deux lignes de l'ouverture ne sont pas des requêtes JSON-RPC.
113. **Jetons et mTLS de la prise TCP du SDK** (EX-6.1 : « par un jeton
     statique ou mTLS (TCP, obligatoire, EX-4.39) », « lui associe l'entrée
     de `sdk.hosts` qui correspond » ; EX-6.10 : pas de ligne de jeton « en
     mTLS » ; table de 15.1, ligne `sdk` : « `tcp_listen` (jeton ou mTLS) » ;
     EX-15.4 ne nomme une liste de jetons que pour `mcp.hosts` et
     `model.hosts`). Jeton : un `match.static_token` de `sdk.hosts` désigne un
     `id` de `mcp.http.static_tokens`, comme la prise TCP des connecteurs ;
     avec `tls` posé, la ligne de jeton passe sur TLS. mTLS : le schéma ne
     donne ni l'autorité des certificats clients de cette prise
     (`$defs/tcp_listen` : `listen`, `client_auth` ∈ {`jeton`, `mtls`},
     `tls` ; `$defs/tls_server` : `cert_file`, `key_file` seulement ; seul
     `model.icap.client_ca` nomme une autorité cliente, pour ICAPS), ni de
     forme de `match` pour un certificat (`$defs/host_connection/match` :
     `peer_user`, `oauth_subject`, `static_token`, `source_addresses`) ; le
     frontal MCP n'avait pas de mise en œuvre à reprendre (`connector_tcp`
     suit désormais la même lecture, par le même code : lecture 134).
     Lecture, par
     les formes les plus proches : l'autorité admise est celle qui suit le
     certificat du démon dans `tls.cert_file` (chaîne PEM ; sans elle, le
     point d'entrée refuse de démarrer, et `client_auth: "mtls"` sans `tls`
     est refusé par la validation) ; le certificat client, vérifié à la
     poignée de main (autorité, validité), est rattaché à l'entrée dont
     `match.peer_user` égale le nom commun (CN) de son sujet — le
     certificat tient lieu d'identité du pair, que la description de
     `client_auth` dit absente sur TCP, et `${peer_user}` de `launched_by`
     en prend la valeur ; `sdk_connected` porte `transport: "mtls"`. Un
     certificat absent, expiré, d'une autre autorité, ou sans entrée est
     refusé (`auth_failed`, `transport: "tls"`, raison
     `certificat:<code>` ou `hote_inconnu`) avant toute lecture.
114. **`finAppel` d'une lecture passante, d'un appel en observation**
     (EX-14.6 : la réponse normale ; table de 6.2 : `{ "seq", "hash" }`). Un
     événement en attente (14.5) n'a encore ni `seq` ni `hash`. Lecture :
     `{ "seq": null, "hash": null }`, mêmes clés que la réponse normale ; de
     même pour un `echangeModele` mis en attente.
115. **Quotas et fin d'appel** (EX-4.47 : refus « au pas 1 »). Refuser un
     `finAppel` ferait perdre l'événement d'un outil déjà exécuté. Lecture :
     les quotas de requêtes, d'octets de pièces et de temps de capture
     s'appliquent à `ouvrir`, `declarerContexte`, `debutAppel` et
     `echangeModele` ; jamais à `finAppel` ni à `fermer`, dont les octets
     sont comptés.
116. **Texte de la reprise à chaud** (EX-12.15 : « la même reprise » ;
     EX-12.14 : `"resultat inconnu : enregistreur arrete pendant le
     relais"`). Lecture : même construction, même pièce, même texte fixe
     (aucune valeur nouvelle) ; `intent_recovered` porte `session_closed:
     true`. Au seul arrêt du démon, rien n'est repris à chaud : la relecture
     du journal d'intention le fait au démarrage (EX-6.13).
117. **Effets d'une reprise d'un appel du SDK** (EX-12.14 pas 2 : effets
     déclarés de la ligne contexte, « sinon pour une classe `ecriture`
     l'effet unique par défaut » ; EX-12.15 : « la même reprise », « c'est
     la relecture du journal d'intention qui fait le travail, pas un code
     spécial du frontal » ; EX-12.12 : le journal d'intention ne porte pas
     la classe, et un `debutAppel` du SDK y écrit pour une `ecriture` comme
     pour une lecture rendue `autorise` sur ticket approuvé). Lecture : les
     deux reprises sont une seule construction (`Coeur._partielReprise`),
     qui tire la classe du nom d'outil de l'intention et de la
     configuration, jamais de la session : pour un outil du SDK, aucune
     classe configurée (lecture 111) et la déclarée n'est pas dans le
     journal, donc « à défaut `ecriture` » (table de 6.2, `debutAppel`) ;
     une lecture approuvée reprise, à chaud comme à froid, porte l'effet par
     défaut (`system` = alias du SDK, `object` = nom déclaré), sauf effets
     déclarés. 13.5 ne dit rien de contraire : seule une lecture **sans**
     intention est perdue sans trace.
118. **Registre de corrélation sans frontal modèle** (EX-5.22, 6.3 : le démon
     applique 5.6 à chaque `debutAppel`). Lecture : avec `sdk.enabled` et
     `model.mode: "desactive"`, le démon tient un registre propre aux
     échanges déclarés, remis aussi au frontal MCP.
119. **Échange déclaré d'un format v0 hors Gemini** (table de 6.2 :
     « l'extraction de 5.5 s'applique » ; EX-6.8 point 4 ne vaut que pour
     `gemini`). Lecture : la pièce « réponse » est la réponse déclarée,
     rédigée, quel que soit `status` (l'objet `noortrace_http_error` de 5.3.1
     pas 7 n'est pas de 5.5) ; `is_error` est le déclaré. Pour `autre`,
     `request.model` est lu dans la requête rédigée (EX-5.19).
120. **Échange déclaré pendant un mode dégradé** (colonne M de 14.2 : un
     échange **relayé** par la passerelle). Lecture : bloquant (`-31010`,
     raison de la panne), sauf en mode « stockage » avec `failure.modele:
     "passant"` et en mode observation, où l'événement est mis en attente
     (lecture 114).
121. **Contexte déclaré et sélecteur d'outil** (8.2, 10.2.2 portée
     `contexte`). L'outil qui citera le document n'est pas connu à
     `declarerContexte`. Lecture : seules les règles de `tools: "*"`
     s'appliquent ; un document au-delà de `limits.piece_max_bytes` est
     refusé par `-31013` (direction `requete`).
122. **Paramètres non prévus** (6.5 : aucun paramètre ajouté ; EX-6.6).
     Lecture : un membre inconnu des paramètres est refusé (`-32602`,
     `parametre_inconnu`), et, comme au pas 1 de 4.4 (EX-4.44), des
     `arguments` dont un nombre n'est pas exactement représentable
     (`nombre_non_representable`).
123. **Identifiants `session` et `call`** (6.2 : chaîne ; EX-6.13 : jamais
     réutilisé). Lecture : `s-<époque sur 20 chiffres>-<n sur 12>` et
     `c-<époque>-<n>`, compteur propre au processus.
124. **Retard de réception** (EX-6.41 : « `ts` de l'événement moins la fin
     déclarée du span, en millisecondes »). Les vecteurs `otel/` (par exemple
     `json-retard`, `gzip-json`) donnent la partie entière de l'écart exact
     en nanosecondes. Lecture : ⌊(ts × 10^6 − fin) / 10^6⌋, 0 si négatif.
125. **Registre de recouvrement** (EX-6.34 : « chaque appel d'outil et chaque
     échange scellé par le frontal MCP, la passerelle ou le SDK », « ni
     persistant, ni reconstruit au redémarrage »). Lecture : il est nourri
     par le cœur après chaque appel durable (relais et reprise à chaud) et
     chaque échange durable du frontal modèle (passerelle, ICAP, miroir) et
     du SDK, y compris un appel ou un échange mis en attente (14.5) et
     scellé plus tard, démon en marche (`viderAttente`) : il est inscrit à
     son scellement, avec la connexion d'hôte gardée en mémoire par
     `mettreEnAttente` ; un événement d'attente scellé au démarrage
     (fichier d'attente d'une époque antérieure) n'y entre pas, le registre
     n'étant pas reconstruit au redémarrage. Le modèle M d'un span venant des pièces rédigées (EX-6.36),
     ses pièces sont calculées en mémoire avant le jugement du recouvrement,
     et ne sont pas stockées pour un span écarté.
126. **Pièce d'enveloppe non rédigeable** (EX-7.7 : `media_type:
     "application/json"` ; EX-8.7 règle 3 : « sans `media_type` »). Lecture :
     la forme `noortrace_non_redigeable` garde la règle d'EX-8.7, sans
     `media_type`.
127. **Membres textuels de l'enveloppe** (EX-6.35). Lecture : la projection
     rédigée porte `name`, `trace_state`, `attributes`, `events[].name`,
     `events[].attributes`, `status.message`, `resource.attributes`,
     `scope.name`, `scope.version`, `scope.attributes` et `schema_url` ; les
     `dropped_attributes_count` de la ressource restent structurels ; un
     membre textuel supprimé par l'action `supprimer` est absent de la pièce.
128. **Raisons du `503`** (EX-6.39). Lecture : stockage, clé, bail perdu ou
     non détenu, horloge, et « attente » (une file d'attente au-delà de ses
     bornes, que l'ingestion ne doit pas dépasser), plus `volume_ingestion`
     (EX-6.28) ; « approbation » est sans effet.
129. **Quotas d'une source** (EX-6.28). Lecture : jugés au pas (d) avec les
     octets déjà reçus ; une requête compte comme en cours une fois son
     corps reçu, jusqu'à sa réponse ; ses octets reçus sont ajoutés une fois
     lus, refusée comprise.
130. **Limitation des échecs d'authentification** (EX-6.37, EX-18.3).
     Lecture : par identifiant de jeton présenté et par connexion HTTP
     (`keep-alive`) ; la métrique `noortrace_otel_requests_total` d'une
     requête non authentifiée porte `source=""`.
131. **Priorité des frontaux interposés** (EX-6.28). Lecture : un événement
     de span attend qu'aucun événement d'un autre frontal ne soit en file de
     l'écrivain ; un lot déjà pris par l'écrivain n'attend plus.
132. **Entiers 32 bits et énumérations** (EX-6.29, EX-6.30 ; « dans les bornes
     du type »). Lecture : `kind` et `status.code` sont des `int32`
     (énumération ouverte) ; en protobuf, un varint d'énumération est lu en
     complément à deux sur 64 bits, puis borné à `int32` ; un compte `uint32`
     au-delà de 2^32 − 1 est refusé (`400`).
133. **TLS de `otel.tls`** (EX-6.40, sans version). Lecture : plancher TLS
     1.2, comme `model.tls` (lecture 74).

Lectures du complément « prise TCP des connecteurs en TLS et mTLS » (§4.7.1,
EX-4.39 ; table de 15.1, ligne `mcp` : « prise TCP des connecteurs
(`connector_tcp`, jeton ou mTLS) ») :

134. **mTLS et TLS de `mcp.connector_tcp`** (EX-4.39 : « Une prise TCP […]
     DOIT exiger un jeton statique […] ou mTLS »). Le schéma a la même lacune
     que pour `sdk.tcp_listen` : `mcp.connector_tcp` est un
     `$defs/tcp_listen` (`listen`, `client_auth`, `tls`), `$defs/tls_server`
     n'a que `cert_file` et `key_file`, et `$defs/host_connection/match` n'a
     pas de forme pour un certificat. Lecture : exactement celle de la
     lecture 113, par le même code (`src/mcp/prise-tcp.mjs`) : l'autorité
     admise suit le certificat du démon dans `tls.cert_file` ; le certificat
     client, vérifié à la poignée de main, est rattaché à l'entrée de
     `mcp.hosts` dont `match.peer_user` égale son nom commun (`${peer_user}`
     en prend la valeur) ; pas de ligne de jeton en mTLS ; le jeton passe sur
     TLS si `tls` est posé avec `client_auth: "jeton"` ; `mtls` sans `tls`
     est refusé par la validation (`controleConnecteurTcp`), une chaîne sans
     autorité au démarrage ; refus consignés `auth_failed` (`transport:
     "stdio"`, `tls: true`, raison `certificat:<code>` ou `hote_inconnu`). Une
     identité par certificat n'est pas un « jeton porteur » d'EX-4.14 :
     `cacheScope` suit la règle de l'identité du pair.
135. **Configuration TLS du connecteur** (§4.7.1, EX-3.3, 19.5 : CT-2 ne dit
     rien de la configuration TLS du connecteur ; EX-3.3 : « ni clé, ni
     stockage, ni politique »). Lecture : la clé de EX-3.3 est la clé de
     signature de l'enregistreur (section 11, EX-11.2 : « Le connecteur
     stdio et le SDK n'ont aucun accès au signataire ») ; la clé d'un
     certificat client est un identifiant de connexion, comme le jeton.
     Comme le jeton (`NOORTRACE_CONNECTEUR_JETON`, jamais sur la ligne de
     commande), elle vient de l'environnement, sous les noms du SDK
     (EX-6.10) au préfixe du connecteur : `NOORTRACE_CONNECTEUR_TLS_CA`,
     `NOORTRACE_CONNECTEUR_TLS_CERT`, `NOORTRACE_CONNECTEUR_TLS_KEY` (chemins
     de fichiers PEM). Avec certificat et clé : mTLS, sans ligne de jeton ;
     avec l'autorité seule : TLS et jeton ; un certificat sans clé, ou une
     prise TCP sans jeton ni certificat, est refusé (code 2) ; plancher TLS
     1.2 (lecture 74).
136. **Reconstruction depuis les copies : outil ou démon** (EX-12.17 : « À
     la reprise d'une instance dont le stockage local est perdu (section
     13), le journal est reconstruit depuis les copies » ; CT-8 §11.4
     chemin B : « la liste des versions sous `<prefix>` (CT-2 EX-17.6 pas 1)
     et leur restauration dans un répertoire neuf » ; CT-8 EX-10.14 :
     `noortrace-ctl worm restaurer`, « l'écrit dans un répertoire neuf,
     jamais sur l'original »). Lecture : la reconstruction est une commande
     d'exploitation, `noortrace-ctl worm reconstruire`, hors du démon ; le
     démon démarre ensuite sur le répertoire reconstruit (`storage.root`) et
     prend, par le magasin de bail, une époque plus grande que toutes celles
     des noms (13.4 ; EX-11.1 de CT-8 : l'époque ne recule jamais). Les pas
     5 à 8 du chemin B (vérification par `verifier-journal.mjs`, ancrage,
     procès-verbal `restauration`) relèvent de CT-8 et ne sont pas écrits
     ici ; la vérification de chaîne de l'outil en tient lieu pour refuser
     un répertoire incohérent.
137. **`created_at` du `journal.json` recréé** (CT-8 §11.4 : recréé « dans
     la forme de CT-2 EX-12.1 avec `recorder.org_id` et
     `recorder.journal_id` de la configuration » ; 12.1 : « écrit à la
     création du journal »). La valeur n'est pas fixée. Lecture : le `ts`
     du premier événement de la chaîne restaurée (le journal a été créé au
     plus tard à cet instant) ; l'heure de la reconstruction placerait la
     première clé hors de sa validité annoncée par `cles.json`, qui part de
     `created_at` (contrôle E-11 de CT-1 en échec, constaté), et le journal
     reconstruit ne serait plus vérifiable. Sans segment, l'heure de la
     reconstruction. `recorder` : la version de ce logiciel.
138. **Version relue et contrôle `sha256`** (EX-10.14 : « compare son
     SHA-256 au registre des copies » ; 12.1 : le registre « ne fait foi de
     rien et se reconstruit depuis la liste des versions » ; tableau de
     CT-8 11.2 : `worm/` sauvegardé par le chemin A). Lecture : avec
     `--registre-copies` (l'archive du chemin A), la version relue est celle
     de la dernière ligne de la clé, et le SHA-256 et la longueur de chaque
     objet relu sont comparés à la ligne (`copie_alteree`, `copie_absente`) ;
     une clé sans ligne (copie postérieure à l'archive) est relue si elle a
     une seule version (`worm_restore_unregistered`) ; sans registre, la
     version unique de chaque clé ; plusieurs versions sans ligne qui les
     départage : refus (`versions_multiples`), le texte ne donnant aucun
     autre critère. Sans registre, l'intégrité repose sur la chaîne
     (continuité des `seq` depuis 1, `prev_hash`, hachages recalculés,
     en-têtes, époques non décroissantes, manifestes recalculés ; les
     signatures ne sont pas vérifiées par l'outil, mais par le démon à sa
     reprise et par `N.verifierJournal`) ; la perte
     du dernier segment fermé n'y est pas décelable (elle ressemble à la
     perte admise du segment ouvert, 13.5) : seul le registre la révèle.
139. **Fichiers relus, fichiers perdus** (CT-8 §11.4 : « les fichiers sans
     copie (intentions, attente, approbations, pièces sans `copy_pieces`)
     sont perdus et listés dans le procès-verbal »). Lecture : sont relus
     les segments, manifestes et signatures, séries des points, fichiers
     d'ancres et pièces ; tout autre objet sous `<prefix>` (dont `gels/`)
     est ignoré ; la synthèse (sortie standard, `worm_restored`) liste
     `intentions/`, `attente/`, `approbations/`, `worm/` et, s'il en
     manque, les pièces référencées absentes ; le procès-verbal lui-même est
     de CT-8 (11.9), non écrit ici.
140. **Restriction du gardien de pose à `ON`** (EX-18.9 : « restreint à `ON`
     là où la restriction est vérifiée (R13-F30) » ; R13-F30 : page AIStor
     de MinIO). Constat sur MinIO DEVELOPMENT.2025-07-23T15-54-02Z (serveur
     communautaire, `test/enregistreur-worm-iam.test.js`) : une politique
     qui autorise `s3:PutObjectLegalHold` sous la condition `StringEquals`
     `s3:object-lock-legal-hold` = `ON` refuse la pose comme la levée (403
     `AccessDenied`, avec ou sans en-tête `x-amz-object-lock-legal-hold`,
     valeur `ON` ou `on`), et autorise les deux sans la condition. La
     restriction n'est donc pas vérifiée sur ce serveur ; le gardien de pose
     y détient le droit entier, comme chez AWS (R13 NV-1).
141. **Serveur S3 qui applique les politiques IAM** (demande du lot : une
     seconde source que LocalStack). Tirages essayés, erreurs exactes :
     `ghcr.io/minio/minio:latest` « denied » ; `public.ecr.aws/minio/minio:latest`
     « not found » ; `registry.access.redhat.com/minio/minio` « not found » ;
     `mirror.gcr.io/minio/minio` « not found » ; `quay.io/minio/minio`
     « 401 UNAUTHORIZED » ; `docker.io/minio/minio` « pull access denied » ;
     `docker.io/bitnamilegacy/minio` « 429 Too Many Requests » ;
     `cgr.dev/chainguard/minio:latest` tiré mais sans `mc` (pas de création
     d'utilisateurs ni de politiques). Retenue :
     `mirror.gcr.io/bitnamilegacy/minio@sha256:8935e75f…09d7` (MinIO
     DEVELOPMENT.2025-07-23T15-54-02Z avec `mc`), qui applique politiques,
     signature SigV4, versions, Object Lock et `If-None-Match`.
142. **Entrées et état du compagnon** (CT-8 EX-3.9 ; fichier Compose de
     CT-8 : `command: ["--racine", "/var/lib/noortrace", "--intervalle-s",
     "60"]`, `TMPDIR: /run/temporaire`, sonde `noortrace-attributs sonde`).
     Lecture : le compagnon ne reçoit ni la configuration ni de signal du
     démon (aucun texte ne prescrit d'interface entre eux) ; il déduit des
     noms de 12.1 le segment courant (le dernier dans l'ordre des noms,
     comme l'écrivain) et le journal d'intention courant (la plus grande
     époque). Un segment qui vient d'être fermé passe de `a` à `i` dans le
     même appel (`chattr -a +i`). `--intervalle-s` est borné à 1..60 (« 60
     secondes au plus ») ; `--une-fois` (un seul passage) sert aux essais et
     aux tâches d'orchestrateur (EX-12.18 : « ou une tâche de
     l'orchestrateur »). La sonde rend 0 si le dernier passage, écrit sous
     `TMPDIR`, a réussi et date de moins de deux intervalles plus 5 s.
     L'image `noortrace/attributs` (étape 7) doit contenir Node.js, ce
     paquet, `chattr` et `lsattr` et l'entrée `/usr/local/bin/noortrace-attributs`.
143. **Attribut `a` et opérations du démon que le texte prescrit**
     (EX-12.18 ; EX-12.10 pas 3 : « tronquer le fichier à la fin de la
     dernière ligne valide (`ftruncate`) » ; EX-12.13 : « un fichier dont
     toutes les intentions sont levées est supprimé à la rotation
     suivante »). Sous `a`, `ftruncate` et la suppression sont refusés
     (`EPERM`) au démon, qui n'a pas la capacité de retirer l'attribut. Pour
     la suppression, lecture : le fichier est gardé et consigné
     (`intention_file_kept`), sa conservation ne nuisant à rien (toutes ses
     intentions sont levées). Pour la troncature, aucune lecture ne la rend
     possible : un segment courant à fin incomplète sous `a` fait échouer
     le démarrage (essai `enregistreur-worm-attributs`, cas « conflit de
     texte ») ; le texte ne dit pas qui retire `a` avant la reprise. Signalé
     au rapport du lot (« À corriger dans CT-2 »).
144. **Clôture interrompue entre le manifeste et sa signature** (CT-1 §10.2 :
     « La signature est portée à côté du manifeste, dans `manifeste.sig` » ;
     EX-12.24 ; contrôle P-5 ; relecture A, R-A-1). Un arrêt brutal entre
     l'écriture de `periode-<start>.json` et celle de `.sig` laissait une
     période close à jamais sans signature (la relecture prend le dernier
     manifeste pour la période précédente). Lecture : au démarrage, avant
     toute écriture, un manifeste sans signature est signé sur ses octets
     présents par la clé qu'il nomme, s'il est exactement celui que la chaîne
     durable donne (recalculé sur les événements de sa période, chaîné au
     manifeste précédent, CT-1 §10.3) ; la remise à l'ancrage (EX-12.27) et
     les copies WORM du manifeste, de la signature et de la série (EX-12.16)
     sont refaites ; `period_signature_restored` est consigné. Le manifeste
     n'est jamais réécrit ; un manifeste que la chaîne ne redonne pas n'est
     pas signé (`manifest_inconsistent`, mode dégradé « stockage » jusqu'à
     intervention).
145. **Points et clôtures au tic sous une horloge qui saute** (EX-7.13 :
     « l'écrivain ne date pas l'événement dans le futur » ; EX-12.24 : instants
     « lu[s] sur l'horloge de 7.4 », « Un point manqué (arrêt, horloge bloquée
     par EX-7.13) n'est pas rattrapé » ; relecture A, R-A-2). Le tic lisait
     l'horloge murale sans le contrôle de saut : un saut le temps d'un tic
     closait des périodes futures, puis le plancher de la dernière clôture
     datait l'événement suivant dans le futur. Lecture : le tic applique la
     comparaison d'EX-7.13 (avance murale depuis l'événement précédent contre
     avance monotone, plus `clock.max_forward_ms`) ; en mode dégradé
     « horloge », ou si cette comparaison révèle un saut (`clock_forward_jump`,
     entrée dans le mode), rien n'est clos ni pointé. La référence reste celle
     de l'événement précédent (texte) ; au redémarrage il n'y en a pas (EX-7.13).
146. **Erreur de `fdatasync` : les lignes non durables quittent le segment**
     (EX-12.8 : l'écrivain « relit le fichier depuis le début pour établir sa
     dernière ligne valide », et « les lignes dont la durabilité n'est pas
     établie sont tenues pour perdues (leurs appels n'ont pas reçu de
     réponse […]) » ; relecture A, R-A-3). Après un `EIO`, les lignes écrites
     restent lisibles dans le cache : la seule relecture les gardait dans la
     chaîne alors que leurs appelants avaient reçu un refus (`-31010`, ou
     `-31017` et l'événement en attente, d'où deux `executee` pour un appel).
     Lecture : le segment est tronqué à la longueur couverte par le dernier
     `fdatasync` rendu (connue de l'écrivain), puis relu ; l'état revient à la
     dernière ligne durable ; `segment_truncated` (raison
     `durabilite_non_etablie`) ; les opérations en attente de `fdatasync`
     sont refusées avant que le segment suivant ne puisse les couvrir ; ce
     segment n'est ouvert qu'après la troncature. De même, les deux lignes
     d'une intention dont le `fdatasync` échoue sont retirées (l'appel n'est
     pas relayé, EX-12.12), sauf bail perdu (EX-13.6 : plus aucune écriture).
147. **Reprise de l'attente scellée une seule fois** (EX-14.10, EX-9.8 ;
     relecture A, R-A-4). Le fichier d'attente n'est supprimé qu'après le
     scellement de ses lignes ; un arrêt entre les deux, ou une ligne dont
     l'événement a été scellé depuis la file en mémoire (sortie du mode sans
     redémarrage : la ligne reste au fichier), faisait sceller le même
     événement une seconde fois. Le format de la ligne (14.5) n'a pas de marque
     de scellement ; lecture : chaque ligne est d'abord cherchée dans la chaîne
     durable. L'événement scellé depuis l'attente porte les huit champs de
     l'événement partiel de la ligne (ou le résultat perdu d'EX-14.10) ; avec
     une intention, c'est l'événement que désigne sa levée, ou à défaut un
     événement non désigné par une autre levée et de `ts` au moins égal à
     `written_at` ; sans intention, son `ts` vaut `max(captured_at, ts
     précédent)` (ou le début de période qui suit une clôture, lecture 3).
     Une ligne retrouvée n'est pas scellée de nouveau
     (`pending_already_sealed`) et son intention est levée si elle ne l'est
     pas.
148. **Magasin de bail `file` : `flock(2)` tenu par `flock(1)`** (13.2 :
     « `flock(LOCK_EX | LOCK_NB)` sur `lease.store.path` ; en cas de succès,
     lire le fichier `path.epoch` […], écrire `epoch + 1`, `fdatasync` » ;
     « Implicite tant que le descripteur est ouvert ; le noyau du système
     libère à la mort du processus » ; EX-13.10, dernier alinéa ; relecture A,
     R-A-5). Remplace la lecture 6 : le fichier verrou portant un PID, repris
     quand ce PID n'est plus vivant, laissait deux détenteurs vivants (course
     de reprise, 13 essais sur 30) et refusait le bail tant qu'un processus
     sans rapport avait repris le PID. Node.js n'offrant pas `flock(2)` sans
     module natif, le verrou est pris et tenu par `flock --exclusive
     --nonblock` d'util-linux (même appel système), lancé par le démon avec un
     tube sur son entrée standard : l'auxiliaire vit tant que le tube est
     ouvert, c'est-à-dire tant que le démon vit ; à la mort du démon (SIGKILL
     compris), le noyau ferme le tube, l'auxiliaire se termine et le noyau
     libère le verrou ; un démon figé le garde. L'époque est incrémentée sous
     ce verrou. Un auxiliaire tué seul libère le verrou : le bail n'est plus
     valide et l'écrivain cesse d'écrire (EX-13.6). Le fichier verrou n'est
     jamais supprimé (le supprimer pendant qu'un autre le tient ouvert
     donnerait deux verrous sur deux fichiers) ; son contenu n'est pas lu.
     Sans `flock(1)`, l'acquisition est refusée (raison `bail`) : l'image du
     démon doit contenir util-linux (essayé avec 2.39.3). Le détenteur du
     descripteur est l'auxiliaire et non le démon lui-même : c'est la seule
     façon conforme sans dépendance native trouvée ; la mort de l'un entraîne
     la libération, comme le texte le demande.
149. **Reconstruction et premier démarrage sur un journal reconstruit :
     signatures, pièces, séries vérifiées** (EX-12.17 ; CT-8 EX-11.6 : « les
     fichiers restaurés sont identiques octet pour octet à ceux que le
     registre des copies, les copies WORM […] désignent » ; CT-8 §11.4
     chemin B, pas 5 (`verifier-journal.mjs … --cles <fichier>`) ; EX-12.10
     pas 2 ; relecture A, R-A-6). Sans registre des copies, seule la chaîne
     prouve l'identité des copies, et elle ne la prouve qu'avec les
     signatures : un segment altéré puis rechaîné (hash recalculés) était
     accepté. Lecture : `noortrace-ctl worm reconstruire` et
     `reconstruireJournal` vérifient tout le répertoire reconstruit
     (`src/verification.mjs`) : chaque ligne comme le dernier segment à la
     reprise (signature sous la clé en vigueur comprise), la chaîne par le
     noyau (E-1 à E-11, C-1 à C-3), chaque manifeste recalculé et sa
     signature, la continuité, chaque série de points, le SHA-256 de chaque
     pièce contre son nom ; les clés sont celles de la chaîne (rotations) et,
     pour la clé initiale, `--cles <cles.json>` (forme de CT-1 §11.2) ou le
     signataire de classe D de la configuration ; une clé introuvable refuse
     (`cle_inconnue`). Le démon, au premier démarrage sur un journal
     reconstruit (segments présents, aucun `intentions/` : l'écrivain le crée
     avant son premier segment et la reconstruction ne le restaure jamais),
     fait la même vérification avant d'écrire (`journal_reconstruit_verifie`,
     anomalie : `segment_corrupted`, intervention). Il ne la fait pas à chaque
     démarrage : EX-12.10 pas 2 dit les segments précédents « réputés fermés
     proprement ; la supervision les contrôle à son rythme » (lecture 153,
     contrôles quotidiens).
150. **Authentification du service d'approbation sur la prise Unix**
     (EX-18.8 : « sur une prise Unix, par l'identifiant d'utilisateur attendu
     du pair (`peer_user`) et un répertoire de prise non inscriptible par les
     hôtes ni par les agents ; en HTTP, par mTLS ou par un jeton » ; « Un
     `token` nul n'est admis que sur une prise Unix dont le pair est
     vérifié » ; CT-3 EX-12.2 : « et TLS hors de la boucle locale » ;
     relecture A, R-A-7). Node.js ne donne pas l'identité du pair d'une
     connexion (`SO_PEERCRED`) sans module natif. Lecture : avant chaque
     message, le client vérifie que la prise est une prise dont le
     propriétaire (le processus qui l'a créée) est `peer_user`, et que son
     répertoire appartient au compte 0 ou à `peer_user` et n'est
     inscriptible ni par le groupe ni par les autres : nul autre ne peut
     alors substituer une prise sous ce nom ; un écart vaut indisponibilité
     (`pair_non_verifie`, raison `peer_user_inconnu`, `proprietaire_prise`,
     `repertoire_inscriptible` ou `prise_absente`), matrice de 14.2. La
     configuration v0 ne porte aucun réglage mTLS du client : une `url` sans
     `token` est donc toujours sans authentification. Validation (pas 3),
     dans tous les environnements (le texte ne les distingue pas) : `url`
     sans `token`, prise sans `peer_user` ni `token`, `http://` hors de la
     boucle locale sont des erreurs ; les bancs d'essai qui emploient un
     service HTTP local lui présentent un jeton. Le corps d'une réponse du service
     est borné à 16 Mio (`TAILLE_MAX_REPONSE_APPROBATION`, aucun texte ne
     fixe la borne) : au-delà, réponse illisible (`trop_grande`).
151. **Serveur stdio en production et utilisateur du démon** (EX-3.5 :
     « En environment: "production", la validation (15.4) refuse un serveur
     stdio sans user, ou dont user est celui du démon, et refuse une commande
     qui n'est pas épinglée » ; relecture A, R-A-8). Le schéma admet
     `user: null` et `integrity: null`. Lecture : en production, `user` nul,
     `integrity` nul, ou une forme `package` que `command` ne contient pas
     tel quel, sont des erreurs ; « l'utilisateur du démon » est celui qui
     exécute la validation (le démon au démarrage et au rechargement ;
     `validate-config` lancée sous un autre compte compare à ce compte).
152. **`noortrace-ctl reload` et `noortrace-ctl clock --accept`** (EX-15.5 :
     « Sur SIGHUP ou la commande noortrace-ctl reload » ; EX-7.13 :
     « confirmation de l'exploitant (noortrace-ctl clock --accept,
     consignée) » ; EX-18.1 : aucune interface d'administration réseau, « la
     gestion passe par la ligne de commande locale (noortrace-ctl, même
     utilisateur que le démon) », surface d'écoute exhaustive ; relecture A,
     R-A-10). Le texte ne dit pas comment la commande joint le démon, et
     interdit toute prise nouvelle. Lecture : la commande trouve le démon
     parmi les processus de son utilisateur (`/proc/<pid>/cmdline` :
     `noortrace --config <fichier>`, résolu dans le répertoire de travail du
     processus, égal à `--configuration` s'il est donné), envoie SIGHUP
     (`reload`) ou SIGUSR2 (`clock --accept` ; aucun signal n'est nommé par le
     texte, SIGUSR1 est pris par Node.js), et lit la réponse que le démon
     consigne dans son journal d'exploitation (`config_reloaded` ou
     `config_reload_rejected` ; `clock_accepted` ou `clock_accept_refused`).
     Codes : 0 fait, 1 refusé, 2 usage, 4 aucun démon ou pas de réponse.
     `clock --accept` ne lève que le mode « horloge » d'un saut en avant :
     après un recul (EX-7.9), l'accepter daterait les événements au `ts`
     précédent, donc dans le futur de l'horloge, ce qu'EX-7.13 exclut
     (`clock_accept_refused`, raison `recul`).
153. **Contrôles périodiques d'EX-17.5 sans support WORM, avec toutes les
     clés** (EX-17.5 : « toutes les heures, après la clôture de période, la
     vérification que la période close a son manifeste et sa signature et
     que la continuité […] tient, […] et le health() du signataire ; une fois
     par jour, la relecture et la vérification complètes des segments fermés
     de la journée » ; relecture A, R-A-11). Ces contrôles ne tournaient
     qu'avec un support WORM, et la relecture quotidienne ne vérifiait que
     la clé courante. Lecture : le cœur les fait toujours
     (`src/controles.mjs`, armé avec les minuteurs), avec les clés de la
     chaîne (rotations, puis signataire pour la clé initiale) ; le lot WORM
     garde la comparaison des copies, la rétention du support et le registre
     des gels. Le contrôle horaire attend 10 s après l'heure pleine (la
     clôture a lieu au tic de l'écrivain) ; « segments fermés de la journée » :
     ceux dont la dernière écriture date de moins d'un jour et ceux que
     l'écrivain de ce processus a fermés (le dernier de l'instance précédente
     compris, EX-13.9), non encore relus.
154. **Clé de signature inconnue à la relecture** (EX-12.10 pas 2 : une ligne
     est valide si sa `sig` « vérifie sous la clé en vigueur »). Remplace la
     lecture 9 : une ligne dont la clé publique est inconnue n'est plus
     acceptée sans vérification. Elle n'est pas tronquée (elle est complète,
     son hash est juste, lecture 2) : `segment_corrupted` (raison
     `cle_inconnue`), mode dégradé « stockage » jusqu'à intervention (rendre
     au signataire la clé, ou donner sa clé publique).
155. **Durabilité des répertoires et fichiers temporaires** (EX-12.5 : « à la
     création d'un segment ou d'une pièce, d'un fsync du répertoire parent » ;
     EX-12.6 ; EX-12.13 : un arrêt entre la ligne intention et la ligne
     contexte est « impossible par construction »). Lecture : la création
     d'un répertoire (`pieces/<xx>`, et les autres) est suivie du fsync de son
     parent ; les deux lignes d'une intention partent dans une seule
     écriture ; les fichiers temporaires `.tmp-*` d'une écriture atomique
     interrompue (rien de durable sous ce nom) sont supprimés au démarrage,
     avant toute écriture (`temporary_files_removed`).
156. **« Même référence qu'un autre secret »** (EX-15.4 pas 3, avertissement
     sur `worm.credentials`). Lecture : deux références désignent le même
     secret si elles ont le même emplacement (`file`, `env` ou `vault`),
     quel que soit `encoding` : `{"file": "/run/secrets/cle-mac-relais"}` et
     la clé du MAC de relais `{"file": "/run/secrets/cle-mac-relais",
     "encoding": "hex"}` donnent l'avertissement.

Lectures des corrections de la relecture B (frontaux) :

157. **Preuve d'identité par fichier non transférable** (EX-4.39 :
     « identifiant d'utilisateur du pair » ; EX-7.3 ; EX-18.1). Node.js 22
     n'offre pas `SO_PEERCRED` sans module natif, et aucune dépendance
     native n'est ajoutée : la preuve de la lecture 31 reste. Elle n'est
     sûre que si aucun pair ne peut renommer le fichier d'un autre sous le
     nom de son propre défi. Lecture : le répertoire de la prise et chacun
     de ses parents appartiennent au démon ou à root et ne sont inscriptibles
     par le groupe ou les autres qu'avec le bit collant ; c'est contrôlé au
     démarrage (refus de démarrer, `répertoire de la prise … :
     repertoire_inscriptible`, `repertoire_proprietaire`) et à chaque preuve
     (`auth_failed`, `reason: "repertoire_prise"`, `detail`) ; un répertoire
     absent est créé par le démon en mode `1770`. Un fichier dont l'instant
     de création (`birthtime`, quand le système de fichiers le donne) précède
     l'envoi du défi de plus d'une seconde est refusé (`preuve`) : un fichier
     du bon propriétaire renommé depuis un autre répertoire ne prouve rien.
     Le protocole du connecteur et des SDK ne change pas. Prises
     `mcp.socket`, `sdk.socket` et du miroir : mode `0660` posé par le masque
     du processus pendant l'appel synchrone qui crée le fichier, jamais par
     un `chmod` après coup.
158. **Copie du journal d'exploitation sur la sortie d'erreur du connecteur**
     (EX-9.7 : « les lignes de niveau `warning` et `error` qui concernent la
     connexion d'hôte de ce connecteur (son `host`, ses requêtes) sont aussi
     écrites sur `stderr` du connecteur »). Le journal est dans le démon, la
     sortie d'erreur dans le processus connecteur. Lecture : le démon envoie
     sur la prise du connecteur la ligne `{"noortrace_journal":<ligne du
     journal>}` (une réponse JSON-RPC du démon commence toujours par
     `{"jsonrpc"`), le connecteur écrit la ligne du journal sur sa sortie
     d'erreur, jamais sur sa sortie standard. Une ligne concerne la
     connexion si son `host` est celui de la connexion **et** si elle est
     consignée pendant le traitement d'une ligne de ce connecteur (contexte
     asynchrone de la connexion) : un autre connecteur du même hôte, un
     serveur d'outils ou le démon n'y sont jamais copiés. Le journal
     d'exploitation offre pour cela `abonner(f)` (INTERFACES.md, rubrique i).
159. **Bornes contre l'épuisement des ressources** (EX-4.37, EX-4.21, EX-4.39,
     EX-4.32 pour le motif « pour qu'un serveur ne puisse pas faire tourner
     le journal d'exploitation »). Le texte ne borne ni les sessions de
     l'ère héritée, ni les enregistrements de continuation, ni la lecture du
     JWKS, ni les lignes qu'un hôte déclenche sans requête. Lecture : au plus
     64 sessions héritées par identité authentifiée et 4 096 en tout, la
     plus ancienne terminée au-delà (l'hôte qui la présente reçoit `404` et
     réinitialise, EX-4.37) ; une continuation est retirée dès qu'elle a
     servi, avec sa session, et au plus 10 000 sont gardées ; le JWKS est lu
     par une seule requête à la fois, en 10 s et 1 Mio au plus ;
     `host_response_ignored` et `host_notification`, que le texte ne
     prescrit pas, au plus 20 par seconde et par connexion, le reste compté
     (`host_lines_dropped`, `lines`).
160. **Quota contrôlé avant l'analyse** (4.4 pas 1 : « Les quotas … sont
     vérifiés ici ; les octets reçus sont comptés même pour une requête
     refusée » ; EX-4.47). Lecture : chaque transport compte les octets dès
     leur lecture (corps refusé par le transport HTTP, ligne au-delà de
     `limits.line_max_bytes` comprises) ; avant toute analyse, un quota
     d'octets reçus ou de temps de capture atteint refuse la requête par
     `-31013` avec `id: null`, puisque l'`id` n'est connu qu'après l'analyse
     (JSON-RPC 2.0, §5 : « If there was an error in detecting the id … it
     MUST be Null ») ; le temps d'analyse d'une requête refusée est compté.
     Ces deux quotas valent pour toute requête du frontal MCP ; les requêtes
     en cours et les octets de pièces restent jugés après l'analyse, pour un
     `tools/call`. Passerelle : quotas contrôlés avant l'analyse du corps,
     corps lu et compté avant un refus sur la chaîne de requête. SDK : le
     contrôle reste après l'analyse, la méthode (que seule l'analyse donne)
     décidant si le quota s'applique (lecture 115 : jamais à `finAppel` ni à
     `fermer`) ; octets et temps d'analyse des refus y sont comptés.
161. **Comparaison des `Mcp-Param-*`** (EX-4.35 : « sentinelle
     `=?base64?…?=` décodée avant comparaison »). Lecture : la valeur reçue,
     sentinelle décodée (base64 canonique, UTF-8 strict, sinon écart), est
     comparée au texte de l'argument primitif (`String(v)`) ; un argument
     absent ou non primitif est un écart (`-32020`).
162. **Algorithme et type de clé d'un jeton OAuth** (EX-4.39 ; RFC 8725
     §3.1). Lecture : `RS256` n'est vérifié qu'avec une clé `RSA`, `ES256`
     qu'avec une clé `EC` P-256, `EdDSA` qu'avec une clé `OKP` Ed25519, et
     jamais avec une clé dont `alg` est autre.
163. **Limitation des échecs de jeton dans chaque chemin** (EX-18.3). Lecture :
     Streamable HTTP du frontal MCP par identifiant de jeton présenté et par
     connexion `keep-alive` ; prise TCP des connecteurs par identifiant de
     jeton (une seule tentative par connexion) ; passerelle par identifiant
     de jeton et par connexion (elle ferme la connexion après un refus). Un
     échec est un `401` (un `403` n'en est pas un) ; un refus pendant la
     limitation est consigné `auth_failed`, `reason: "jeton_limite"`, comme
     la prise du SDK, et ne prolonge pas la limitation.
164. **`Mcp-Session-Id` inconnu** (EX-4.34 : ignoré en ère moderne ; EX-4.37 :
     `404` après la fin d'une session héritée). Lecture : l'ère d'un POST
     vient de son corps (`_meta` moderne) ; celle d'un GET ou d'un DELETE de
     l'en-tête `MCP-Protocol-Version` (`2026-07-28` : `405`, sinon `404`).
165. **Politique d'une version introuvable** (EX-7.5 SG-4, SG-7 ; EX-7.21 RL-4 ; EX-9.4 : « `E` l'`expire_after_ms` de
     la version de politique de cet événement … et non celui de la version en
     vigueur » ; CT-3 7.6 : « `E` ≤ 86 400 000 ms »). Une pièce de politique
     absente ou illisible au démarrage (purge d'EX-12.20, copie restaurée) est
     consignée `policy_piece_unavailable`. Lecture : une vérification qui ne
     peut pas être faite échoue (SG-4 `echeance_depassee`, SG-7
     `auto_approbation` quand la remise porte des approbateurs, RL-4), jamais
     sautée ; une politique présente sans `separation.self_approval:
     "interdite"` (règles opaques des vecteurs de CT-2) n'exige rien de SG-7.
     L'expiration par le noyau seul attend `request_ts + 86 400 000 +
     timeout_ms`, jamais avant l'échéance réelle : le ticket reçoit une
     décision (CT-3 EX-7.25) sans qu'un approbateur perde son délai. La
     relecture C proposait de garder `E` avec la ligne `retenue` ; EX-12.23
     fixe les membres de cette ligne (`{ "kind": "retenue", "ticket",
     "request_seq", "request_hash", "approver_set" }`) : non fait, sans
     changement de CT-2 (relecture C, R-C-3).
166. **Message qui n'est pas une remise** (EX-7.19 pas 2 : « il inscrit la remise … puis il applique SG-1 à
     SG-7 »). Lecture : la ligne `remise` d'EX-12.23 ne se forme que d'un objet
     qui a `ticket`, `remise_id`, `approval.decision` et `approver_set` ; un
     message sans eux n'est pas une remise, rien n'est inscrit et SG-1 le
     refuse (`remise_mal_formee`) ; son jeu ne serait de toute façon jamais
     exploitable (EX-9.4). Seul un échec d'entrée-sortie de l'écriture fait
     entrer en mode « stockage » (relecture C, R-C-11).
167. **Sortie du mode « stockage » après un échec des fichiers des approbations** (EX-7.19 pas 2 ; EX-14.11 : la sortie du mode « stockage » est
     « l'ouverture et le `fdatasync` d'un nouveau segment » ; EX-12.8). Lecture :
     l'échec est traité comme une panne du segment (segment fermé et tronqué à
     sa longueur durable, `writer.signalerPanneStockage`), d'où la sortie par
     un nouveau segment au tic ; les fichiers des approbations sont rouverts
     (relus, dernière ligne incomplète coupée) avant la ligne suivante, jamais
     complétés derrière une ligne dont la durabilité n'est pas établie
     (relecture C, R-C-11).
168. **`held` établi au scellement** (EX-7.19 pas 3 : « `held`, vrai si et seulement si le noyau retient une
     requête de ce ticket et va la relayer »). Lecture : `held` est constaté
     dans le même tour que la remise de la décision à la rétention, après le
     scellement, de sorte que la fin de la rétention (`hold_timeout_ms`) ne
     s'intercale plus ; une décision `refuse` n'est jamais relayée : `held`
     faux. Le `consommer` du relais attend la fin de l'`acquitter` (CT-3 T18
     n'admet `consommer` qu'en `approuve`).
169. **Nouveaux essais jusqu'au succès** (CT-3 12.7 : `ouvrir` « nouvel essai jusqu'à succès » ; `charger`,
     `acquitter`, `consommer`, `expiration` « nouvel essai » ; EX-7.18 ;
     EX-7.20). Lecture : sans borne de nombre, délai croissant de 50 ms à 5 s,
     un seul envoi en cours par message ; une erreur portant une raison de
     CT-3 §12.8 est une réponse (finale pour `charger` et `expiration`, et pour
     `ouvrir` et `consommer` selon EX-7.18 et EX-7.20) ; `indisponible`, une
     réponse illisible, un pair non vérifié sont une absence de réponse. Un 401
     et un 5xx `requete_invalide` (erreur interne du service, dont l'échec
     d'écriture de son état) ne répondent pas au message : `indisponible`.
     Seule la réponse au dernier `charger` envoyé est adoptée (EX-7.4 ; CT-3
     EX-12.5) (relecture C, R-C-5, R-C-6).
170. **`consommer` au redémarrage** (EX-7.20 : « dont le délai de reconnaissance (`approval.at + E`) court
     encore »). Lecture : `E` de la version de la `retenue`, à défaut la borne
     de 86 400 000 ms ; au plus quatre envois simultanés (relecture C,
     R-C-10).
171. **Une décision par ticket** (SG-3 ; CT-3 14.2 : « Seconde décision pour un ticket décidé : SG-3 »).
     Lecture : la vérification et le scellement d'une remise et l'expiration
     par le noyau seul d'un même ticket sont sérialisés ; SG-3 est vérifiée de
     nouveau juste avant le scellement (relecture C, R-C-4).
172. **Limites du texte constatées par la relecture C** (a) Après un `acquitter` `scelle` perdu, la remise re-présentée est
     refusée `ticket_deja_decide` et le service s'aligne par T14, dont les
     membres (CT-3 EX-12.9 : « pour `ticket_deja_decide`, `seq`, `hash`, `at`,
     `decision` et `approval` ») ne portent pas `held` : une approbation
     relayée par une requête retenue n'y est pas marquée servie ; RL-3 empêche
     un second relais. (b) Un `consommer` qui arrive avant cet alignement est
     refusé `requete_invalide` (EX-7.8 : « `consommer` hors `approuve` et hors
     T22 »), réponse finale (CT-3 EX-12.10, EX-7.20) : le ticket finit
     `approbation_non_consommee` (T19). Ni l'un ni l'autre ne se corrige sans
     changer CT-3 ; à proposer (section « À corriger dans CT-2 »).

Lecture de la relecture B, suite (lot SDK Python) :

173. **`subscriptions/listen`** (EX-4.15 : « le frontal ouvre
     `subscriptions/listen` avec `toolsListChanged: true` » ; « notifie
     l'hôte : `notifications/tools/list_changed` sur le flux
     `subscriptions/listen` ouvert par un hôte moderne qui a demandé
     `toolsListChanged` » ; renvoi à la page Subscriptions, R1 Q9, sans le
     format). CT-2 ne donne ni la place du filtre ni l'accusé ; le schéma de
     la révision 2026-07-28 lu dans `@modelcontextprotocol/core` 2.2
     (`SubscriptionsListenRequestParams`, `notifications/subscriptions/acknowledged`,
     clé `io.modelcontextprotocol/subscriptionId`), dépendance de
     `@langchain/mcp-adapters` 2.0.1, les donne. Lecture : le filtre est
     `params.notifications` (sans lui : `-32602`, `notifications_requis`) ;
     le frontal répond d'abord par l'accusé, qui porte les types honorés
     (`toolsListChanged` seul : ressources et prompts ne sont pas relayés,
     EX-4.25) et l'id de la requête sous `_meta`, puis envoie sur ce flux
     les `notifications/tools/list_changed` marquées du même id ; le flux
     finit à l'annulation de l'hôte (`notifications/cancelled`, fermeture
     du flux HTTP) ou avec la session (`host_subscription_opened` consigné à
     l'ouverture). Vers un serveur moderne, le frontal envoie
     `{"notifications":{"toolsListChanged":true},"_meta":…}` ; cela remplace
     la forme `{"toolsListChanged":true,…}` de la lecture 38.

Lectures du lot « signataires » (classes A, B et C, §11) :

174. **Classe A sans module natif** (EX-11.10 ; « Node.js n'a pas PKCS#11 »
     n'est pas du texte : c'est l'état de Node.js 22). Lecture : le démon
     parle au module du fabricant par un auxiliaire, `python3 -I -S
     src/signataires/pkcs11-auxiliaire.py <module> <jeton>` (bibliothèque
     standard seule : `ctypes`), lignes JSON sur stdin/stdout ; le PIN est
     la première ligne de stdin (jamais un argument ni une variable que
     `/proc` montre) ; l'auxiliaire reçoit l'environnement du démon sans
     aucune variable désignée par une référence de secret (EX-15.3). Motifs :
     `C_Sign` est bloquant — en processus, la boucle d'événements serait
     arrêtée et `signer.timeout_ms` (EX-11.18) intenable, alors que
     l'auxiliaire est tué à l'échéance et la seconde tentative en relance
     un ; une bibliothèque de fabricant qui plante n'emporte pas le démon ;
     un module natif npm (`pkcs11js`) serait compilé à l'installation, ce que
     `npm ci --ignore-scripts` ne fait pas, et chargerait le code du
     fabricant dans le démon. L'image du démon qui sert la classe A doit
     contenir `python3` (CT-8 tient déjà la classe A pour une adaptation du
     client).
175. **`CKA_EC_PARAMS` et `CKA_EC_POINT`** (EX-11.10 : « la configuration dit
     laquelle le jeton attend » ; « Public key bytes in little endian order
     as defined in RFC 8032 »). Le schéma n'a aucun membre pour la forme de
     `CKA_EC_PARAMS` (`additionalProperties: false`) et le démon ne crée
     jamais de clé (EX-11.4) : il lit la clé et admet les deux formes
     (curveName `13 0c 65 64 77 61 72 64 73 32 35 35 31 39`, OID `06 03 2b
     65 70`), refuse toute autre, et consigne la forme lue (`signer_ready`,
     `pkcs11.ec_params`). SoftHSM2 2.6.1 rend `CKA_EC_POINT` enveloppé dans
     un OCTET STRING DER (`04 20` ‖ 32 octets) : les deux formes (32 octets
     bruts, ou `04 20` ‖ 32) sont admises, la forme lue consignée
     (`pkcs11.ec_point`).
176. **`CKM_CLOUDHSM_EDDSA`** (EX-11.10 : « admis par table de
     correspondance quand la configuration le nomme »). Sa valeur numérique
     est dans l'en-tête `cloudhsm_pkcs11_vendor_defs.h` du kit d'AWS
     CloudHSM, que ni CT-2 ni les pages de R3 ne citent ; elle n'a pas été
     lue. Lecture : l'entrée existe dans la table, sans valeur ; un démon qui
     la nomme refuse de démarrer avec ce motif, plutôt que d'employer une
     valeur devinée. À compléter dans CT-2 (section « À corriger »).
177. **Clé suivante chez le backend** (`signer.rotation.next_key_id` est le
     seul membre ; EX-11.15 (1) : « leurs identifiants sont inscrits dans
     `signer.rotation.next_key_id` »). Lecture, alignée sur les exemples
     (15.3 : `key_label` égal au `key_id` ; CT-8 : clé Transit nommée
     `rec-sinistres-2026-01`) : la clé suivante se nomme `next_key_id` chez
     le backend — étiquette PKCS#11, nom de clé Transit, alias
     `alias/<next_key_id>` du compte et de la région de `key_arn` (AWS),
     `…/cryptoKeys/<next_key_id>/cryptoKeyVersions/1` du trousseau de
     `key_version` (Google) ; en classe C, comme en classe D, fichiers du
     même répertoire nommés `<next_key_id>` suivi de l'extension du fichier
     courant (`sealed_seed_file`, ou `public_file` et `private_file` du TPM),
     chargés s'ils existent, et contexte de chiffrement dont `key_id` est
     `next_key_id`.
178. **Non-exportabilité vérifiée au démarrage** (EX-11.5 : « la clé est
     créée non exportable et le reste »). Lecture : quand le backend le dit,
     le démon le contrôle et refuse sinon : clé Transit `exportable: true`
     ou `allow_plaintext_backup: true` ; clé PKCS#11 `CKA_EXTRACTABLE` vrai
     ou `CKA_SENSITIVE` faux (ou sans `CKA_SIGN`). AWS KMS et Google Cloud
     KMS n'exportent jamais une clé asymétrique : rien à contrôler. Le type
     est contrôlé aussi : Transit `ed25519`, KMS `ECC_NIST_EDWARDS25519`
     avec `ED25519_SHA_512`, Google `EC_SIGN_ED25519` (EX-11.1).
179. **Contexte de chiffrement et fichier scellé** (EX-11.9 : « un contexte
     de chiffrement (AWS `EncryptionContext`, Google
     `additionalAuthenticatedData`) porte `org_id`, `journal_id` et
     `key_id` »). AWS : la carte `{org_id, journal_id, key_id}`. Google :
     les données associées sont des octets ; le texte n'en fixe pas
     l'encodage : JCS (RFC 8785) du même objet. Azure : `unwrapKey` n'a pas
     de données associées pour `RSA-OAEP-256` ni `A256KW`, et EX-11.9 ne
     nomme qu'AWS et Google : aucun contexte ; `kid` de la réponse doit
     désigner la clé et la version configurées. Le fichier scellé contient
     les octets du chiffré tels que le service les rend, décodés de leur
     base64 (`CiphertextBlob`, `ciphertext`, `value` de `wrapKey`). La
     graine déchiffrée doit faire exactement 32 octets.
180. **TPM 2.0** (EX-11.9 ; schéma : `sealed_seed_file` requis, `wrap.tpm2`
     porte `public_file`, `private_file`, `pcrs`). L'objet scellé de
     `tpm2_create` est le couple (`-u`, `-r`) : `sealed_seed_file` n'est pas
     lu pour `tpm2`. Le parent est la clé primaire du propriétaire au
     gabarit `tpm2_createprimary -C o -g sha256 -G ecc` : la cérémonie
     scelle sous ce parent. Le TPM est désigné par `TPM2TOOLS_TCTI` de
     l'environnement du démon ; les objets transitoires et sessions laissés
     par les outils sont purgés (`tpm2_flushcontext -t -s -l`), sans quoi
     un TPM sans gestionnaire de ressources se remplit (essayé sur swtpm).
181. **SoftHSM2 en production** (EX-11.8 : « En `recorder.environment:
     "production"`, la classe D est refusée » ; 11.2 : SoftHSM2 « assimilé à
     D » ; EX-15.4 pas 3 : « avertissement si `signer.backend.module`
     désigne un module PKCS#11 logiciel connu (`libsofthsm2.so`), qui vaut la
     classe D (11.2) bien qu'il soit déclaré en classe A »). Le texte de la
     validation est explicite : un avertissement, pas un refus ; la
     configuration déclare la classe A, que EX-11.8 ne refuse pas. Le code
     garde l'avertissement (configuration.mjs, inchangé) ; le parcours de
     classe A sur SoftHSM2 est fait en développement. Un refus serait un
     écart au texte de 15.4 : à trancher par CT-2 (section « À corriger »).
182. **Identités IAM** (EX-11.18 : « identité IAM (AWS, Google) » ; le schéma
     n'a aucun membre d'identifiants pour `aws-kms`, `gcp-kms` ni
     `azure-keyvault`). Lecture : l'identité vient de l'environnement du
     démon, comme le font les kits des fournisseurs : AWS
     `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` ;
     Google `GOOGLE_APPLICATION_CREDENTIALS` (fichier de compte de service ;
     jeton par assertion JWT RS256, portée `cloudkms`) ; Azure
     `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`. Points
     d'accès : ceux des fournisseurs, ou `AWS_ENDPOINT_URL_KMS` /
     `AWS_ENDPOINT_URL`, `CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS`,
     `AZURE_AUTHORITY_HOST` (variables de ces kits). Non faits : identité
     d'instance (métadonnées EC2, GCE, identité managée Azure), identifiants
     de conteneur et de fédération (identités d'instance AWS et Google :
     lecture 193).
183. **Clé publique et clé inscrite** (EX-11.18 : « comparée à la clé
     inscrite au registre quand elle est disponible »). Le démon ne lit pas
     encore le registre (CT-4, lot suivant). Lecture : la clé publique lue
     au démarrage est comparée à celle qu'annonce la chaîne pour la clé
     courante (événement de rotation, CT-1 §8) ; une différence refuse le
     démarrage (`signer_key_mismatch`, `demarrage_refuse : cle`, code 2).
     Pour la clé initiale, aucune clé n'est annoncée : une clé différente
     fait échouer la vérification des événements relus (EX-12.10).
184. **Rotation planifiée** (EX-11.15 : « La configuration PEUT fixer une
     période » ; pas (3) « à l'instant choisi »). Lecture : au tic, hors mode
     dégradé, quand `planned_every_days` jours sont écoulés depuis l'entrée
     en vigueur de la clé courante (`ts` de la rotation qui l'a annoncée, ou
     du premier événement) et que la clé `next_key_id` est lisible chez le
     backend, le démon fait la rotation (`tournerCle`) ; sinon il consigne
     `key_rotation_unavailable` une fois et réessaie toutes les
     `health_interval_ms`. L'inscription préalable au registre (pas 2)
     n'est pas contrôlée (lecture 183).
185. **Version de clé Transit** (Vault et OpenBao : `auto_rotate_period`,
     rotation interne de la clé). Lecture : la version dont la clé publique a
     été lue est épinglée (`key_version` de `sign`) et la signature rendue
     doit porter le préfixe `vault:v<cette version>:` : une rotation faite
     dans le backend ne change pas la clé qui signe sans événement de
     rotation dans le journal.
186. **`health()` périodique** (EX-11.18 : « Appelée par la supervision toutes
     les `signer.health_interval_ms` » ; 14.2 : « signataire en erreur ou
     hors délai (`sign`, `health`) »). Lecture : au tic, toutes les
     `health_interval_ms`, hors mode « clé » ; une réponse autre que `ok`
     consigne `signer_unavailable` (`raison: "health"`) et fait entrer en
     mode dégradé « clé ». Transit : lecture de la clé ; AWS : `DescribeKey`
     (`Enabled`) ; Google : état `ENABLED` de la version ; PKCS#11 :
     `C_GetSessionInfo` (session rouverte une fois) ; classes C et D :
     `ok` (fonction du démon).
187. **Borne d'AWS KMS** (EX-11.7 : « 4096 pour AWS KMS ») : un message de
     plus de 4096 octets est refusé par le backend avant l'appel, quelle que
     soit `signer.max_message_bytes` ; aucune règle du pas 3 n'impose 4096
     dans la configuration (le texte n'en écrit pas). Format de la signature
     rendue non documenté (NV-11) : 64 octets attendus, vérifiés.
188. **« Répertoire » d'EX-13.5 (1), et une instance dépassée n'écrit rien**
     (EX-13.5 (1) : « l'époque de l'en-tête DOIT être strictement supérieure à
     la plus grande époque présente dans les noms de fichiers du répertoire » ;
     EX-12.1 : « un répertoire par journal » ; EX-13.1 : « Un enregistreur
     n'écrit un journal que s'il détient le bail » ; EX-13.6 : « cesse
     d'écrire » ; défaut D-1, révélé par TE-11). Lecture : « le répertoire »
     est celui du journal (12.1), avec tous ses sous-répertoires dont les noms
     portent une époque (`segments/`, `intentions/`, `attente/`,
     `approbations/`, `worm/`) : le repreneur ouvre d'abord son segment et son
     fichier d'intention (13.4 pas 5), jamais d'abord un fichier d'attente, et
     une lecture limitée à `attente/` laissait l'ancienne instance y ouvrir
     `attente-<son époque>` après la reprise. « Strictement supérieure » se
     compare aux époques des autres écrivains : les fichiers de l'époque même
     de l'écrivain sont les siens (une époque par acquisition, EX-13.4) ; la
     première ouverture d'une époque reste contrôlée strictement sur les
     segments (relecture). Au-delà de l'ouverture, une instance qui n'est plus
     détentrice, ou dont l'époque est dépassée par une autre présente dans le
     journal, n'écrit plus rien : ni événement, ni intention (le contrôle
     précède l'écriture des deux lignes), ni levée, ni point, ni clôture, ni
     fichier d'attente (`GardeEpoque` : listes relues quand le `mtime` d'un
     sous-répertoire change ou n'est pas assez ancien) ; elle consigne
     `lease_lost` (`cause: "epoque_superieure_presente"`) et entre en mode
     dégradé « bail ». Le fichier d'attente d'EX-4.46 et d'EX-14.8 n'étant
     écrit qu'« au mieux », un événement en attente d'une instance sans bail
     reste en mémoire seulement ; si elle s'arrête, l'intention ouverte donne
     l'événement de reprise du repreneur (EX-4.46, dernière phrase ; 13.5).
     Les pièces, sans époque et adressées par leur `sha256`, restent écrites
     selon EX-14.8 (« si le stockage des pièces répond encore »).
189. **Attente déjà couverte par une reprise** (EX-4.46 : l'événement en
     attente est scellé « à la place d'un événement de reprise » ; 13.5).
     Lecture : à la reprise d'un fichier d'attente, une ligne dont l'intention
     est déjà levée par un autre événement durable de la chaîne (l'événement
     de reprise d'un repreneur) n'est pas scellée : il n'y aurait sinon deux
     événements pour une écriture exécutée une fois, et l'intention levée deux
     fois. Ligne `pending_superseded` (`pending_id`, `intent_id`, `seq` de
     l'événement qui la couvre) ; le fichier est supprimé comme les autres
     fichiers d'attente d'époque inférieure.
190. **« Déploiement à plusieurs instances »** (EX-17.2 : `data` « porte
     `instance_id` dans un déploiement à plusieurs instances »). Le démon ne
     peut pas compter les instances ; le texte les attache au magasin de bail :
     CT-8 IC-10 (« Pour une instance : magasin `file` […]. Pour deux
     instances : base PostgreSQL ou grappe etcd »), table des déploiements de
     CT-8 (« `file` sur un hôte ; `postgresql` ou `etcd` pour deux
     instances »), CT-2 EX-13.10 (« déploiement à bascule entre hôtes
     (`lease.store` `postgresql` ou `etcd`) »). Lecture : avec `postgresql` ou
     `etcd`, chaque ligne du journal d'exploitation du démon porte
     `data.instance_id` = `recorder.instance_id` (le détenteur inscrit au
     magasin, 13.2) ; avec `file`, aucune. Les lignes que `noortrace-ctl`
     écrit avec la configuration d'une instance suivent la même règle
     (`noortrace-ctl worm releve` écrit dans le journal de l'instance).
191. **Fin d'une connexion ICAP refusée** (EX-5.3 : un client hors
     d'`allowed_sources` ou sans certificat admis n'obtient aucune
     transaction ; EX-15.4 : un démarrage refusé s'arrête avec le code 2).
     Lecture : la réponse `403` (ou d'erreur) annoncée `Connection: close`
     partie, la prise est détruite sans attendre que le pair ferme son côté
     (Squid 6.13 gardait le sien : la prise retenait l'arrêt du démon jusqu'au
     délai de drain, et un client refusé pouvait garder des prises ouvertes ;
     défaut révélé par TI-19). Un démarrage refusé (par exemple une adresse
     d'écoute déjà prise, `EADDRINUSE`) ferme aussi les fils de rédaction,
     sans quoi le processus restait vivant après `demarrage_refuse`.


Lectures du lot « signataires », reprise :

192. **Références `{ "vault" }`** (15.2 : « Lecture KV dans Vault ou OpenBao, à
     l'adresse et avec le jeton de `signer.backend` quand il est de type
     `vault-transit`/`openbao-transit`, sinon avec `VAULT_ADDR` et
     `VAULT_TOKEN` de l'environnement » ; « Lue au démarrage »). Lecture :
     `GET <adresse>/v1/<path>` avec `X-Vault-Token` (et `X-Vault-Namespace`
     du backend) ; réponse de KV version 2 (`data.data[field]`, l'exemple du
     texte est `kv/data/…`) ou version 1 (`data[field]`) ; la valeur est une
     chaîne, décodée ensuite selon `encoding`. La lecture, réseau, précède la
     résolution des autres références (pas 4 ; `lireSecretsVault`, puis
     `resoudreSecrets(config, { vault })`), au démarrage et au rechargement
     (pas 1 à 4 sur le nouveau document, EX-15.5). Un jeton de
     `signer.backend` lui-même référencé dans Vault est refusé (il faudrait
     ce jeton pour le lire). Erreurs rapportées sur le pointeur, sans valeur
     (`config_invalid`, code 2).
193. **Identités d'instance** (EX-11.18 : « identité IAM (AWS, Google) » ;
     Azure n'y est pas nommé et n'est qu'une enveloppe de classe C : son
     identité managée n'est pas faite, seule l'application Entra ID par
     secret client l'est). AWS : sans variables d'identifiants, le rôle de
     l'instance par IMDSv2 (`PUT /latest/api/token`, puis
     `…/iam/security-credentials/<rôle>`, identifiants temporaires gardés
     jusqu'à cinq minutes de leur fin) au point
     `AWS_EC2_METADATA_SERVICE_ENDPOINT` ; l'adresse par défaut d'IMDS est une
     adresse IP de lien local, que les règles de ce dépôt n'admettent pas dans
     un fichier livré : elle n'est pas écrite, et l'exploitant pose la
     variable (à trancher à l'intégration). Google : sans
     `GOOGLE_APPLICATION_CREDENTIALS`, le jeton du compte de service de
     l'instance (`http://metadata.google.internal/computeMetadata/v1/instance/
     service-accounts/default/token`, `Metadata-Flavor: Google` dans la
     requête et exigé dans la réponse ; hôte remplacé par `GCE_METADATA_HOST`).
     Éprouvés contre des serveurs simulés écrits d'après les pages
     officielles relues (EC2 : « Configure the Instance Metadata Service
     options », « Retrieve security credentials from instance metadata » ;
     Compute Engine : « Authenticate workloads using service accounts »).
194. **`noortrace-ctl cle rotation-urgence`** (CT-8 EX-10.14 : « exécute les
     pas de CT-2 EX-11.16 dans leur ordre » ; EX-11.16 : inscription de la
     nouvelle paire, événement de rotation, puis révocation de l'ancienne
     `chainKey`). Le démon n'a pas de client du registre (CT-4) : avec
     `anchoring.registry.enabled`, le pas 1 ne peut pas précéder le pas 2 et
     la commande est refusée (`registre_non_branche`) ; registre désactivé,
     les pas 1 et 3 sont sans objet (consigné). Rotation vers
     `signer.rotation.next_key_id`, refusée en mode dégradé (la clé courante
     doit être utilisable), sans clé suivante distincte ou lisible. Même
     mécanisme que `reload` (EX-18.1 : aucune prise) : signal SIGURG (ignoré
     par défaut ; SIGUSR1 ouvrirait l'inspecteur de Node.js), et seulement si
     `noortrace-ctl` a écrit la demande `<ops_log.path>.rotation-urgence`
     (supprimée à la lecture) : un signal seul est ignoré et consigné
     (`key_rotation_emergency_ignored`). Réponse lue au journal
     d'exploitation : `key_rotation_emergency` (code 0) ou
     `key_rotation_emergency_refused` (code 1).
195. **Rapprochement des signatures** (CT-7 EX-3.7 ; CT-9 rattache TA-31,
     « procédure du client ; outil de rapprochement », à l'étape 4). Outil
     `noortrace-ctl cle rapprocher --configuration <f> --audit <journal>
     [--cle] [--de] [--a]`, hors du démon : opérations de signature réussies
     du journal d'audit `file` de Vault/OpenBao sur `<mount>/sign/<nom>`,
     comparées aux objets signés du journal (événements, contresignatures de
     rotation, manifestes, points de contrôle) ; code 3 si le compte du backend
     est supérieur (incident, CT-7 4.6), 0 sinon (un compte inférieur n'est
     pas qualifié). Le démon signe aussi hors du journal : signatures de test
     (démarrage, sortie du mode « clé ») et tentatives qui n'ont pas servi ;
     il les consigne désormais (`signer_test_signature`,
     `signer_unavailable.key_id` et `.tentatives`) et l'outil les retire du
     compte, sans quoi chaque démarrage serait un faux incident. Seuls les
     journaux d'audit de Vault/OpenBao sont lus (CloudTrail, Cloud Audit Logs :
     non faits).

196. **Secrets du document `ancrage-v0`** (CT-2 §15.2 : « une référence
     d'emplacement, jamais une valeur » ; CT-5 règle `secrets` d'AN-1 ; TA-41).
     Le schéma `ancrage-v0` refuse déjà une chaîne en clair à la place d'une
     référence ; le démon résout les seuls pointeurs `/rfc3161/providers/<i>/auth/secret`
     (quand `auth.method ≠ aucune`) et `/opentimestamps/headers_source/auth`
     par `resoudreSecret` (`env`, `file`, `vault`), et une référence qui ne se
     résout pas (`env` absente) refuse le démarrage de l'ancrage sans
     arrêter l'enregistreur : `anchoring_not_started` `secret_non_resolu`
     avec le pointeur, jamais la valeur ; ni la file, ni `acquisitions.ndjson`,
     ni le journal ne portent une valeur de secret (AN-43, vérifié par
     l'essai).
197. **Ancrage en défaut, démon en service** (CT-5 EX-4.8 : « une
     configuration invalide … l'enregistreur continue » ; CT-2 §14.2, lignes
     « Ancrage » : « jamais bloquant »). Lecture : tout défaut du branchement
     autre qu'une classe de clé de chaîne non servie (lecture 200) laisse le
     démon démarrer ; `anchoring_not_started` nomme la raison une fois, puis
     chaque remise de point ou de clôture est consignée `anchor_pending`
     (`reason` : `configuration_invalide`, `composant_non_demarre`, …) ; les
     points et les manifestes sont produits normalement.
198. **Signatures de clôture** (CT-4 §8.2, pas 3 à 5 : « la demande de
     clôture signée au seuil par les approbateurs » ; `contexte.signaturesCloture`
     du composant). Le démon ne détient pas les clés des approbateurs : il
     relaie `submitPeriod` quand l'exploitant a déposé la demande signée
     (forme `demande_signature`, `operation` `cloture`, vérifiée par OP-6 et
     OP-7) sous `<journal>/registre/demande-cloture-<period_hash>.json` ;
     sans elle il rend `null` et le composant consigne `period_close_delegated`
     (`signatures_en_attente`) puis réessaie au tic ; une demande d'une autre
     période ou invalide est consignée `period_close_request_refused`.
199. **Manifeste d'instance du registre** (CT-4 §4.8 ; CT-2 §15 : aucune clé
     ne le désigne). Lu dans `instance-registre.json` à côté du document
     `ancrage-v0` (`evm_chain_id`, `bft_chain_id`, `contracts`, `validator_sets`,
     `fees`) ; absent avec `anchoring.registry.enabled` : `instance_registre_absente`,
     ancrage non démarré. À inscrire dans CT-2 : `anchoring.registry.instance`.
200. **Clé de chaîne de classe A à C** (EX-11.19 : « la clé de chaîne suit
     les classes de §11 »). Seule la classe D est servie par ce lot ; une
     autre classe refuse le démarrage du démon (`demarrage_refuse : ancrage :
     classe_cle_chaine`, code 2) avec un message qui nomme l'étape 7, plutôt
     qu'un démarrage sans registre que l'exploitant ne verrait pas.
201. **Canal de `noortrace-ctl ancrage`** (EX-18.1 : aucune prise ; lecture
     152). Le même fichier de demande que `cle rotation-urgence`
     (`{ demande: "ancrage", commande, id }`) et le signal SIGURG ; le démon
     répond au journal d'exploitation (`anchoring_state`, `anchoring_metrics`,
     `provider_qualification_withdrawn`, refus `anchoring_ctl_refused` :
     `ancrage_non_configure`, `composant_non_demarre`, `identifiant_absent`, `prestataire_inconnu`, `commande_inconnue`) ;
     `metriques` lit en plus `/metrics` de `supervision.health_listen` et
     imprime les lignes `noortrace_anchor*`.
202. **Rotation d'urgence au registre** (EX-11.16 ; lecture 194 :
     `registre_non_branche`). Inchangée par le lot F2 : le composant de CT-5
     encode les appels d'inscription et de révocation et leurs condensés
     OP-6/OP-7, mais n'envoie que `anchorCheckpoint`, `submitPeriod` et la
     clôture, et CT-4 §7 fait signer révocation et nouvelle inscription par
     les approbateurs au seuil : relayer la rotation exige leur outil de
     signature et deux envois absents du lot. Le refus reste nommé.
203. **Horloge du démon injectable** (§7.4 ; règle 2 d'`INTERFACES.md` du
     composant). `principal(argv, io)` accepte `io.horloge` (`murale`,
     `monotone`, `programmer`) pour les essais qui lancent le démon réel
     en processus enfant avec une horloge réglable ; sans elle, l'horloge
     de §7.4 et `setTimeout` du démon. `superviserProcessus` (signaux,
     fichier de demande) est exporté de `cli.mjs` pour ces essais ; `bin/noortrace`
     n'a pas changé.
204. **Bornes de la file d'attente, `pending_max_ms` et contrôle avant le
     relais** (EX-14.9 ; matrice de 14.2, ligne « Mémoire »). Correction :
     `pending_max_ms` n'était pas codé ; `coeur.attenteBornee()` (`coeur.mjs`)
     teste les trois bornes, dont l'âge de l'événement le plus ancien
     (horloge murale du cœur moins son `captured_at`, défaut 300 000 comme
     les deux autres défauts, dans le même code ; le schéma rend le membre
     obligatoire sans défaut). De plus, les bornes n'étaient constatées
     qu'à la mise en attente, après le relais : la lecture ou l'échange qui
     atteignait la borne était relayé et son événement perdu
     (`event_lost`, `exchange_lost`) hors du mode observation. Le frontal
     MCP et le SDK (`_etatPanne`) et le frontal modèle (`blocage`) les
     interrogent au pas 7, avant le relais : au-delà, `-31010`
     `reason: "attente"` (`503 noortrace_degrade` pour un échange), mode
     dégradé `attente`, ligne `pending_limit_reached` (`events`, `limit` :
     la borne atteinte), une fois par entrée. Aucun contrôle périodique
     n'est ajouté : EX-14.9 rend bloquantes les lectures et les échanges
     qui se présentent, et EX-17.5 ne prescrit aucun contrôle de la file ;
     la sortie reste celle d'EX-14.10 (file scellée, `pending_flushed`).
     Essai : `test/enregistreur-coeur-attente-bornes.test.js`.
205. **Ligne `disk_low`** (14.2, ligne « Disque presque plein »). Le refus
     d'écrire une pièce sous `storage.min_free_bytes` faisait entrer le mode
     « stockage » (`degraded_enter`, `event: "disk_low"`) sans la ligne
     `disk_low` que la matrice nomme ; elle est consignée (`free_bytes`,
     `min_free_bytes`) par `MagasinPieces.verifierEspace` à l'entrée sous le
     seuil, une fois jusqu'au retour au-dessus (voir 206). Même essai.
206. **Disque presque plein : démarrage, ouverture de segment, contrôle
     périodique** (14.2, colonne « Détection » : « avant ouverture de
     segment, avant l'écriture de chaque pièce, et toutes les 10 s » ;
     EX-15.4 pas 5, EX-9.8). Le démon refusait de démarrer sur un disque
     sous `storage.min_free_bytes` (exception à l'écriture de la pièce de
     politique) ; seule une configuration invalide empêche le démarrage
     (14.2, lignes « Configuration invalide »), et EX-12.10 pas 1 fait
     d'une anomalie du stockage au démarrage un mode dégradé. Le démon
     démarre donc en mode dégradé « stockage », sans segment ouvert ; les
     pas 2 à 4 d'EX-9.8 (reprises, attente d'un arrêt précédent,
     politique) sont faits au tic qui ouvre le nouveau segment, avant tout
     autre événement, et les refus de la politique (EX-10.21, EX-15.8)
     restent des refus de démarrer. L'écrivain vérifie l'espace avant
     d'ouvrir chaque segment ; `coeur.tic()` le vérifie toutes les 10 s
     (horloge monotone du cœur) et, sous le seuil, ferme le segment comme
     après une panne (EX-12.8) ; la sortie suit EX-14.11, quand l'espace
     revient. Essais : `test/enregistreur-coeur-attente-bornes.test.js`.
207. **Sortie du mode « stockage » après un échec d'écriture de pièce**
     (EX-12.8, EX-14.11). Un échec d'écriture d'une pièce faisait entrer le
     mode « stockage » sans fermer le segment : la reprise du tic ne
     rouvrait rien et le mode n'était jamais quitté sans
     `degrade.sortir`. `coeur.ecrirePiece` ferme désormais le segment
     (`ecrivain.signalerPanneStockage`, comme EX-7.19 pas 2) : le tic
     ouvre et synchronise un nouveau segment quand le stockage répond, ce
     qui fait sortir du mode, puis la file est scellée (EX-14.10). Les
     essais existants qui entrent eux-mêmes dans le mode
     (`degrade.entrer("stockage")`) en sortent eux-mêmes : ils ne sont pas
     changés. Même essai.
208. **Lecture qui constate la panne de stockage** (14.2, colonne L ;
     EX-14.8 : pièces gardées en mémoire si le stockage des pièces ne
     répond plus). Le frontal MCP et le SDK rendaient `-31010 stockage` à
     la lecture dont l'écriture des pièces (pas 4) constatait la panne ;
     après la panne, ils réévaluent le pas 7 : une lecture passante sans
     ticket est relayée et son événement mis en attente ; sinon la
     raison de la panne constatée est rendue. Même essai.
209. **Raison de `call_blocked` côté modèle avec `stockage` et `attente`**
     (EX-14.4 : deux pannes simultanées se traitent par la plus
     restrictive). Avec `failure.modele: "passant"`, `stockage` seul laisse
     passer l'échange et `attente` le bloque : la raison consignée est
     `attente` (elle était `stockage`, première de la liste). Même essai.
210. **Jauge `noortrace_pending_oldest_ms`** (§17). Elle n'était jamais
     posée ; elle vaut l'âge, à l'horloge murale du cœur, de l'événement en
     attente le plus ancien (0 pour une file vide), mise à jour à la mise en
     attente, au scellement de la file et à chaque tic. Même essai.
211. **Hashes de la période pour l'admission d'un point** (CT-5 EX-5.3 :
     le composant reçoit les hashes de la période ; EX-12.8 : l'écrivain
     ferme le segment à chaque clôture). `lireHashesPeriode` relisait tous
     les segments du journal à chaque point : le délai d'admission croissait
     avec l'historique (épreuves de l'étape 5, campagne de mesures). Il garde
     désormais, par segment, taille, date de modification et bornes des
     horodatages de ses événements, et ne relit pas un segment inchangé
     dont les bornes sont hors de la période ; un segment modifié, nouveau
     ou recouvrant la période est relu. Le résultat est inchangé (mêmes
     hashes, même ordre par `seq`). Essai : « contexte du composant,
     lireHashesPeriode … » de `test/enregistreur-ancrage-exigences.test.js`
     (racine égale à celle du manifeste, nombre de segments relus).

### Corrections de CT-2 révision 0.7 (pièces d'événements en attente perdues)

Essais : `test/enregistreur-coeur-pieces-perdues.test.js` (chaque titre nomme
l'exigence ; sortie avant correction : refus de démarrer
`pièce non stockée avant le scellement (EX-8.9)`, et pièce à deux membres
produite par la sortie du mode dégradé).

212. **EX-14.18 (nouvelle), EX-8.9 (exception unique), EX-12.10 pas 5,
     EX-9.8 pas 3.** Le rejeu du fichier d'attente au démarrage
     (`coeur._reprendreAttente`) cherchait les pièces de la liste `pieces`
     de la ligne ; quand l'une manquait, il remplaçait le résultat par la
     pièce à deux membres puis l'écrivain refusait de sceller (les autres
     références manquantes restaient exigées) : le démon refusait de
     démarrer. Désormais, une pièce manque quand une référence sans `value`
     de l'événement partiel (`intent`, `execution.arguments`,
     `execution.result`, éléments de `context`) désigne un `sha256` sans
     fichier sous `pieces/` (`coeur._piecesManquantes`) ; l'événement est
     scellé à sa place (ordre de `captured_at`, `ts = max(captured_at, ts
     précédent)`, `policy_version` de capture), `execution.is_error = true`,
     `execution.result` = référence de la pièce JCS intégral
     `{"missing_pieces","noortrace_attente":"pieces perdues pendant le mode degrade","pending_id","result"}`
     (`pieceAttentePiecesPerdues`, `src/pieces.mjs`), écrite avant le
     scellement ; autres références gardées, `policy.redaction` recalculé
     (`partielPiecesPerdues`, `src/capture.mjs`) ; l'écrivain ne réclame pas
     les seules pièces nommées (`sceller(…, { piecesPerdues })`,
     `src/ecrivain.mjs`). Aucun mode dégradé n'est entré. Le même chemin sert
     la bascule (13.5) : le repreneur rejoue les fichiers d'attente des
     époques inférieures.
213. **EX-14.18 pas 6, EX-17.2, 17.4.** Ligne `pending_pieces_lost`
     (composant `noyau`, niveau `error`, `seq` nul ; `data` : `events`,
     `seqs` croissants, `pieces` = nombre de `sha256` distincts manquants),
     une par rejeu où au moins un événement a été scellé selon EX-14.18.
     L'alerte « Pièces en attente perdues » n'est pas levée par le démon :
     les alertes de 17.4 sont des règles d'exploitation (CT-8) sur le journal
     d'exploitation et les métriques ; la ligne en est la condition.
214. **EX-14.10 (modifiée).** `coeur.viderAttente` écrivait les pièces
     gardées en mémoire en ignorant les échecs, puis scellait l'événement
     avec la pièce à deux membres `{"noortrace_attente":"resultat perdu
     pendant le mode degrade","pending_id"}` quand une écriture avait échoué
     (événement scellé avant ses pièces). Désormais chaque événement est
     scellé après l'écriture de toutes ses pièces ; un échec laisse cet
     événement et les suivants en attente, dans leur ordre, jusqu'au tic
     suivant. `pieceAttentePerdue` est retirée. Défaut corrigé au passage :
     un échec retirait de la file, sans les sceller, les événements qui
     suivaient l'événement fautif (l'essai de la jauge
     `noortrace_pending_oldest_ms` de
     `test/enregistreur-coeur-attente-bornes.test.js` passait grâce à ce
     retrait ; il passe sans changement).
215. **§14.2, ligne « Pièces d'événements en attente perdues » (TE-16).**
     Rejouée sur le démon réel `bin/noortrace` (même fichier d'essai) : santé
     `ok`, lecture et écriture relayées, `pending_pieces_lost` au journal
     d'exploitation. Le dossier exporté d'un tel événement est vérifié par
     les deux vérificateurs (binaire Go, `scripts/verify/dossier.mjs` en
     boîte noire) : verdict `valide`, E-6 réussi, que les pièces absentes
     soient non fournies ou que seules les pièces présentes soient fournies
     (`--pieces`) ; une pièce fausse fournie sous un `sha256` manquant fait
     échouer E-6 (témoin).

## À corriger dans CT-2

- **Signataires** (lot « signataires » ; lectures 175, 176, 177, 181) : le
  schéma n'a pas de membre pour la forme de `CKA_EC_PARAMS` qu'EX-11.10
  fait porter par la configuration ; la valeur de `CKM_CLOUDHSM_EDDSA`
  n'est pas écrite ; la clé suivante n'a pas de localisateur propre chez le
  backend (`next_key_id` seul) ; SoftHSM2 en production est un
  avertissement en 15.4 alors que 11.2 l'assimile à la classe D, refusée par
  EX-11.8. Propositions : un membre `ec_params` (`curveName` ou `oid`), la
  valeur du mécanisme avec sa source, un localisateur de la clé suivante
  par backend, et une décision explicite pour SoftHSM2.

- **Alignement T14 et consommation** (relecture C ; lecture 172). CT-3
  EX-12.9 ne donne pas `held` à un `acquitter` `refuse` `ticket_deja_decide`,
  et EX-7.8 refuse un `consommer` hors `approuve` par `requete_invalide`, que
  CT-3 EX-12.10 et CT-2 EX-7.20 tiennent pour final : après un `acquitter`
  `scelle` perdu, une approbation relayée peut rester non marquée servie et non
  consommée dans le service. Proposition : `held` aussi dans T14, et
  `consommer` sur un ticket `a_remettre` dont la décision est connue du noyau
  rendu non final (ou différé jusqu'à l'alignement).
- **Garde de E pour l'expiration par le noyau seul** (relecture C ; lecture
  165). Proposition : `expire_after_ms` dans la ligne `retenue` d'EX-12.23,
  pour que l'échéance se recalcule sans la pièce de politique.
- **Coffre des originaux et pièces rédigées égales** (relecture B, R-B-5).
  EX-10.22 : « chaque pièce rédigée a un homologue chiffré […], nonce de
  12 octets aléatoire par fichier, données associées = le `sha256` de la
  pièce rédigée […], nom de fichier = `sha256` de la pièce rédigée », et
  « rien dans l'événement ne le référence » ; CT-7 EX-3.11 : « le
  déchiffrement d'une pièce », consigné « avec le `sha256` de la pièce ».
  Deux appels d'arguments différents peuvent donner la même pièce rédigée
  (EX-4.21 le dit : « deux IBAN différents donnent tous deux
  `[REDIGE:iban]` ») : un seul homologue existe alors sous ce nom, le
  second original n'est pas gardé (consigné `vault_original_kept`), et le
  déchiffrement demandé pour le second appel rend l'original du premier.
  Garder plusieurs originaux sous ce nom ferait plusieurs homologues d'une
  pièce, et l'accès, qui ne désigne qu'une pièce, ne saurait lequel rendre
  sans rendre à tort celui d'un autre appel ; les rattacher à leur événement
  est impossible au dépôt (fait à la rédaction, avant l'événement, qui ne
  référence pas le coffre). Aucune correction conforme au texte : le code
  n'est pas changé. À trancher par CT-2 (par exemple : homologue nommé par
  le `sha256` de l'original, ou par l'`intent_id`, et accès qui désigne
  l'événement).
- **Lignes consignées pour chaque refus de quota** (EX-4.47 : « refusée au
  pas 1 par `-31013` […] et consignée »). Une fois son quota d'octets
  atteint, un hôte fait consigner une ligne `call_blocked` par requête,
  même de quelques octets : il peut faire tourner le journal
  d'exploitation et effacer une trace comme `tool_definition_changed`, ce
  qu'EX-4.32 interdit pour la sortie d'erreur d'un serveur. Le code consigne
  chaque refus, comme le texte l'exige ; une borne de débit (comme celle
  d'EX-4.32) est à écrire dans CT-2.

## Tests

Depuis la racine du dépôt, après `npm ci` :

```sh
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-annexe-a.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-journal.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-reprise.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-config.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-approbations.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-attente-bornes.test.js
NOORTRACE_VERIFIER_BIN=<binaire noortrace-verifier> npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-pieces-perdues.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-redaction.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-redaction-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-mcp-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-mcp-exigences.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-mcp-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-mcp-tls.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-politique-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-politique-exigences.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-politique-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-exigences.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-hostiles.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-icap.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-squid.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-miroir.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-securite.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-exigences.test.js
NOORTRACE_VERIFIER_BIN=<binaire Go de CT-6> npx hardhat --config hardhat.config.mjs test test/enregistreur-ancrage-parcours.test.js
NOORTRACE_VERIFIER_BIN=<binaire Go de CT-6> npx hardhat --config hardhat.config.mjs test test/enregistreur-ancrage-exigences.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-journal-soi.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-signataires-exigences.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-signataires-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-attributs.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-restauration.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-iam.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-ha-exigences.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-ha-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-otel-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-otel-exigences.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-sdk-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-sdk-exigences.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-sdk-client.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-sdk-parcours.test.js
```

`enregistreur-worm-exigences`, `enregistreur-worm-restauration`,
`enregistreur-worm-iam`, `enregistreur-ha-exigences` et
`enregistreur-ha-parcours` lancent de vrais services dans Docker, images
épinglées par condensé : un service S3 à Object Lock (LocalStack, qui met
en œuvre versions, rétention par défaut COMPLIANCE et GOVERNANCE, *legal
hold*, `If-None-Match` et `Content-MD5`, sans contrôle IAM ni de
signature), un service S3 qui applique les politiques IAM, la signature
SigV4 et Object Lock (MinIO DEVELOPMENT.2025-07-23T15-54-02Z, image
`bitnamilegacy/minio` d'un registre miroir public : les registres de
l'image officielle ont refusé le tirage, lecture 141), PostgreSQL 16 et
etcd 3.5 ; les conteneurs sont arrêtés et supprimés avec leurs volumes
(`docker rm -f -v`) à la fin et à la sortie du processus, les répertoires
temporaires supprimés même en échec. Sans Docker, leurs cas sont en attente et
leur titre nomme la condition manquante. Azure Blob et Google Cloud Storage
n'ont aucun émulateur du stockage immuable de niveau version ni de la
rétention par objet : leurs requêtes de gel et de lecture d'état sont
éprouvées contre un simulateur écrit d'après les pages que CT-2 cite
(`test/fixtures/enregistreur-worm/simulateur-azure-gcs.mjs`, R13-F16,
R13-F19, R13-F22 à R13-F24).

- `enregistreur-coeur-vecteurs` : `jcs-integral`, `evenements/journal-demo`
  reconstruit octet pour octet par l'écrivain (événements, segment, journal
  d'intention, manifeste de clôture), part de §8 de `pieces-mcp`,
  `pieces-modele` et `redaction/cas.json`, inventaire des fichiers rejoués et
  de ceux des lots suivants ;
- `enregistreur-coeur-annexe-a` : l'annexe A de CT-2, octet par octet ;
- `enregistreur-coeur-journal` : un journal produit par le cœur (échanges,
  appels, refus, approbation, rotation, points, clôture) vérifié par le noyau,
  et le dossier minimal de l'appel approuvé vérifié par le noyau et par le
  binaire Go (construit par `verificateur/scripts/construire.sh` avec
  go1.27.3 ; sans lui, ce test est en attente) ;
- `enregistreur-coeur-reprise` : processus tué pendant l'écriture, segment
  déchiré, octets nuls, intention ouverte, corruption, levée implicite,
  panne du signataire après relais ;
- `enregistreur-coeur-config` : `validate-config`, refus de démarrer, classe D
  en production, horloge qui recule ou saute, rechargement ;
- `enregistreur-coeur-approbations` : EX-7.16, SG-, mode dégradé, expiration
  par le noyau seul, canal HTTP ;
- `enregistreur-redaction` : vecteurs `redaction/` (politiques, motifs, cas,
  dans le fil appelant et par les fils de calcul), pièces rédigées de
  `pieces-mcp/appels` et de `journal-demo`, EX-10.1 à EX-10.24 en réussite et
  en échec, détecteurs sur entrées hostiles, budget, fils de calcul, coffre,
  `validate-config`, rechargement ;
- `enregistreur-redaction-parcours` : un frontal simulé fait traverser le cœur
  à des captures sensibles ; pièces rédigées par `pii-v1` avant hachage, aucun
  clair dans le stockage, le journal d'exploitation et les métriques ;
  journal vérifié par le noyau ; dossier de l'appel relayé, pièces fournies à
  part, vérifié par le noyau et par le binaire Go (en attente sans
  go1.27.3).
- `enregistreur-mcp-vecteurs` : chaque transcription de
  `pieces-mcp/appels` rejouée de bout en bout par le frontal (hôte simulé,
  serveur stdio factice, horloge des horodatages) : lignes envoyées au
  serveur et rendues à l'hôte octet pour octet, événement, pièces stockées,
  journal vérifié par le noyau ; `pieces-mcp/agregation` ; appels de seq 3
  et 5 de `journal-demo` (champs des événements publiés) ;
- `enregistreur-mcp-exigences` : EX-4.3 à EX-4.50, EX-7.2, EX-7.3, 14.1 à
  14.3, EX-17.2 en réussite et en échec ; entrées hostiles ; prise Unix
  (preuve d'identité, refus), prise TCP à jeton, Streamable HTTP, OAuth,
  serveur HTTP en amont ;
- `enregistreur-mcp-parcours` : de vrais processus (connecteur, serveurs
  d'outils stdio moderne et hérité, hôtes moderne, hérité et HTTP), chaque
  appel scellé, période close, journal vérifié par le noyau, dossier de
  chaque appel vérifié par le noyau et par le binaire Go (en attente sans
  go1.27.3) ; puis le démon réel `bin/noortrace --config` avec le frontal ;
- `enregistreur-mcp-tls` : `mcp.connector_tcp` en mTLS et en TLS avec
  jeton (lectures 134, 135), avec le connecteur réel `bin/noortrace-connecteur`
  et un serveur d'outils stdio réel : certificat valide rattaché à sa
  connexion d'hôte et appel scellé ; autorité étrangère, certificat expiré,
  sans certificat, certificat sans entrée refusés ; jeton sur TLS accepté,
  jeton faux refusé ; `mtls` sans `tls` refusé par la validation ;
  arguments TLS incomplets du connecteur refusés (autorité et certificats
  générés par `openssl`) ;
- `enregistreur-politique-vecteurs` : `pieces-mcp/appels/approbation-*` et
  `journal-demo` seq 5 à 7 rejoués de bout en bout (frontal, moteur de
  politique, cœur, service simulé d'après CT-3 §12) ; politiques valides et
  invalides de `spec/vecteurs/ct-3` (CT-3 EX-4.2, AP-1 à AP-4) ;
- `enregistreur-politique-exigences` : EX-7.4, EX-7.14 à EX-7.23, EX-9.4,
  EX-12.23, cases de 14.2 du service d'approbation, modes `erreur`,
  `retenir` et observation, EX-15.4 pas 3 et 6, EX-15.8, EX-18.8, en réussite
  et en échec ; entrées hostiles (service muet, réponse illisible, jeton
  refusé, ticket inconnu, remise rejouée, horloge qui recule) ;
- `enregistreur-politique-parcours` : un hôte réel (connecteur) traverse le
  mandataire ; le vrai service d'approbation (`paquets/approbation`) tourne
  en processus, évalue la politique et décide sur les votes EIP-191 des
  comptes de test déposés par son canal de la console ; lecture relayée,
  paiements retenus puis approuvé (intention par référence), refusé, expiré
  (mode `retenir`), mode `erreur`, mode observation, chaque appel scellé,
  période close, journal vérifié par le noyau, dossier de chaque appel
  vérifié par le noyau et par le binaire Go (en attente sans go1.27.3) ;
  puis le démon réel, joint au même service, tué (SIGKILL) pendant une
  rétention, redémarré, la ré-émission retenue, approuvée et relayée ;
- `enregistreur-modele-vecteurs` : chaque cas de `pieces-modele` à travers
  la passerelle réelle vers un fournisseur simulé qui rend les octets
  publiés : refus (statut, corps, `Content-Type`, rien relayé, aucun
  événement), cible et corps reçus par le fournisseur, réponse rendue octet
  pour octet, forme consolidée, appels demandés, pièces stockées, champs de
  l'événement ; `gemini-sdk-*` par les fonctions de dérivation ; échanges de
  seq 2, 4 et 8 de `journal-demo` et corrélation de seq 3 et 5 ;
- `enregistreur-modele-exigences` : EX-5.1, EX-5.2, EX-5.7 à EX-5.13,
  EX-5.19 à EX-5.26, EX-5.28 à EX-5.33, EX-5.36, EX-8.5 à EX-8.7, colonne M
  de 14.2, EX-14.16, 13.5, EX-17.2 et EX-17.3 en réussite et en échec ;
- `enregistreur-modele-hostiles` : analyseur SSE (fins de ligne, marque
  d'ordre d'octets, UTF-8 invalide, chaque transcription découpée à
  l'octet), événements mal formés et index hors bornes, imbrication et
  tailles extrêmes, en-têtes en double, corps invalides, fournisseur qui
  coupe ou répond autre chose que du HTTP, flux d'octets aléatoires, client
  qui se déconnecte ;
- `enregistreur-modele-parcours` : un agent réel (processus Node) parle aux
  quatre formats à travers la passerelle (en flux puis hors flux) et appelle
  l'outil demandé par le mandataire MCP (serveur d'outils stdio lancé par le
  démon) ; chaque échange et chaque appel scellé, chaque appel corrélé,
  période close, journal vérifié par le noyau, dossiers d'un échange et d'un
  appel vérifiés par le noyau et par le binaire Go (en attente sans
  go1.27.3) ; puis le démon réel `bin/noortrace --config` avec la
  passerelle, arrêt propre, et démon tué pendant un échange en vol (13.5) ;
  enfin le démon réel en mode `icap` (mandataire HTTP qui parle REQMOD et
  RESPMOD) et en mode `miroir` (équipement de copie simulé, processus
  `bin/noortrace-miroir`), quatre formats scellés, période close, journal
  vérifié par le noyau, dossier d'un échange par le noyau et par le binaire
  Go ;
- `enregistreur-modele-icap` : client ICAP simulé d'après RFC 3507 (messages
  construits octet par octet : `Encapsulated`, sections HTTP, `chunked`,
  Preview, `ieof`) : OPTIONS, codes d'erreur et `ISTag`, adresses sources,
  ICAPS avec certificat client généré à l'exécution, REQMOD et RESPMOD en
  réussite, blocages (EX-5.7, EX-5.29, EX-5.32, EX-5.33, hôte inconnu,
  colonne M, quota), identifiant au MAC faux, corrélation heuristique,
  requête inconnue, délai sans RESPMOD, flux coupé, panne après le REQMOD
  (EX-14.12), entrées hostiles, mandataire HTTP pour les quatre formats ;
- `enregistreur-modele-squid` (TI-19 de CT-9) : Squid 6.13 réel, construit
  avec OpenSSL (`squid-openssl` 6.13-2+deb13u3, image du Dockerfile de
  `test/fixtures/enregistreur-modele/squid`, base épinglée par condensé,
  paquets lus dans un instantané daté de l'archive Debian), ssl-bump vers
  le fournisseur simulé en HTTPS, ICAP (REQMOD, RESPMOD) vers le démon réel
  en mode `icap` ; même échange par la passerelle d'un démon réel
  (référence) et par Squid, événements comparés ; lien ICAP relevé
  (`ISTag`, statuts, `X-Noortrace-Exchange` dans la requête encapsulée par
  RESPMOD) ; hôte inconnu (entrée `inconnu`, puis blocage en REQMOD) ;
  client ICAP refusé ; période close, journal vérifié par le noyau,
  dossiers par le noyau et le binaire Go ; sans Docker ou sans `openssl`,
  en attente avec la condition ;
- `enregistreur-modele-miroir` : couples de la prise (réussite, `is_error`,
  copie tronquée, borne, refus sans événement, entrée `"inconnu"`, EX-5.32),
  mode dégradé (attente puis scellement, `exchange_lost`), quotas sans
  effet, lignes hostiles, adaptateur (réassemblage HTTP/1.1 découpé à
  l'octet, copie coupée, octets illisibles), processus
  `bin/noortrace-miroir`, de bout en bout pour les quatre formats ;
- `enregistreur-worm-vecteurs` : `spec/vecteurs/ct-2/worm/` (requêtes,
  états, périmètres, gardes, levées) rejoués contre leur attendu, fichiers
  valides pour `worm-v0` ; clé de copie d'EX-12.29 sur le segment de
  `journal-demo` ; exemples calculés de 12.11 (liste de 673 octets,
  enregistrement `pose` de 811 octets, suite d'empreintes, requêtes
  d'EX-12.39) ; formes d'échéance d'EX-12.33 ; SigV4 sur les exemples
  publiés par AWS ;
- `enregistreur-worm-exigences` (S3 réel) : EX-12.16, EX-12.17, EX-12.29 à
  EX-12.33, EX-13.5 (2), copy_pieces, panne du support et balayage ;
  EX-17.5 à EX-17.7 (contrôles, relevé, versions inattendues, marqueur,
  registre des gels, gel levé hors de l'outil, registre falsifié) ; outil de
  gel (pose, demande, levée, levée par la même personne, après sept jours,
  identifiants de l'écrivain, support injoignable, anomalies, gels qui se
  chevauchent, reprise) ; Azure et GCS contre le simulateur ;
- `enregistreur-ha-exigences` (PostgreSQL et etcd réels) : EX-13.1 à
  EX-13.10, 13.2, 13.4 : époque strictement croissante, second détenteur
  refusé, perte au-delà du TTL, validité monotone et saut de l'horloge
  murale, partition réseau simulée, bail repris par une autre instance,
  bail perdu pendant une écriture (après le fdatasync), époque qui recule,
  fichiers d'une époque supérieure, redémarrage, instance passive, clé du
  MAC différente, fourche, règles de configuration, `instance_id` du journal
  d'exploitation (EX-17.2) ; sans Docker : défaut D-1 (instance sans bail
  ou d'époque dépassée : ni attente, ni intention, ni événement ; époque
  supérieure lue dans tout le répertoire du journal ; attente couverte par
  une reprise jamais scellée, lectures 188 à 190), port d'écoute pris
  (EADDRINUSE : démarrage refusé avec le code 2, relance des outils de test
  sur d'autres ports) ;
- `enregistreur-ha-parcours` (deux démons réels, magasins et support
  réels) : pour PostgreSQL puis etcd, A écrit, B passif rend `-31010
  bail_non_detenu`, A tué (SIGKILL) pendant un relais d'écriture, B prend
  le bail avec une époque plus grande et produit l'événement de reprise ;
  période close à l'heure suivante ; chaque segment fermé et chaque clôture
  copiés et verrouillés en COMPLIANCE ; gel posé et levé par
  `bin/noortrace-ctl` ; journal vérifié par le noyau ; dossiers d'un
  événement de A et d'un événement de B vérifiés par le noyau et par le
  binaire Go (en attente sans go1.27.3) ; puis deux démons qui se disputent
  le journal (SIGSTOP au-delà du TTL, SIGCONT) ;
- `enregistreur-worm-attributs` (compte 0, ext4 ou système de fichiers à
  attributs, `setpriv`) : démon réel lancé sans `CAP_LINUX_IMMUTABLE`
  (`setpriv --bounding-set=-linux_immutable`), compagnon réel
  (`bin/noortrace-attributs --une-fois`) : `a` sur le segment courant et le
  journal d'intention, `i` sur les segments fermés et les manifestes ; le
  démon continue d'écrire par son descripteur ; réécriture, troncature,
  suppression par un autre processus refusées ; retrait de l'attribut
  refusé sans la capacité et sous un compte non privilégié ; reprise avec
  fichier d'intention gardé ; scellement refusé sous une époque
  inférieure ; sonde. En attente, titre nommant la condition, hors compte 0,
  sans `setpriv` ou sur un système de fichiers sans attribut `a` ;
- `enregistreur-worm-restauration` (S3 et PostgreSQL réels) : démon A
  écrit, copies faites, stockage local de A détruit ; `bin/noortrace-ctl
  worm reconstruire` (processus réel) depuis le S3, avec et sans registre ;
  démon réel B qui reprend sur le répertoire reconstruit avec une époque
  plus grande ; journal accepté par `N.verifierJournal`, dossiers d'un
  événement restauré et d'un événement de B valides pour le noyau et le
  binaire Go ; échecs : copie manquante, copie altérée (registre, chaîne),
  segment manquant, copie d'une autre version, destinations refusées ;
- `enregistreur-worm-iam` (MinIO réel, politiques IAM appliquées) : rôles
  d'EX-18.9 posés par politiques ; copies du démon avec le seul rôle
  Écrivain ; refus du serveur (403) pour l'Écrivain sous `<prefix>gels/`,
  hors des sous-préfixes, suppression, contournement, gel, rétention,
  configuration et politique du bucket ; signature fausse ; Lecteur en
  lecture seule (et reconstruction avec ses identifiants) ; gel posé et
  levé par les gardiens, refusé au Lecteur ; COMPLIANCE contre le compte
  racine ; constat sur la clé `s3:object-lock-legal-hold` (lecture 140) ;
- `enregistreur-modele-securite` : quotas d'EX-4.47 sur la passerelle
  (requêtes en cours, octets reçus, octets de pièces, temps de capture,
  mode observation), jeton OAuth d'EX-5.8 point 2 (valide, refusé pour
  chaque cause, configuration refusée au démarrage), TLS de `model.tls` avec
  des certificats générés à l'exécution par `openssl` (poignée de main,
  autorité inconnue, nom faux, TLS 1.1 refusé face à un témoin qui
  l'accepte, certificat illisible : démarrage refusé) ;
- `enregistreur-otel-vecteurs` : les 48 cas de `otel/` (B.8) envoyés en HTTP
  au serveur OTLP réel de l'ingestion, chaîne propre à chaque cas : statut,
  type de contenu, corps JSON ou protobuf octet pour octet, `Retry-After`,
  forme normalisée, issues et raisons, pièces (octets et références),
  événements (hash et signature), `overlap_seq`, `lag_ms` ;
- `enregistreur-otel-exigences` : EX-6.23 à EX-6.41 et les règles du pas 3
  pour `otel`, en réussite et en échec, contre un démon en processus (lots
  JSON et protobuf : chemins, méthodes, ordre des décisions, gzip et bombe
  gzip, bornes et quotas, priorité des autres frontaux, décodage hostile,
  clés en double, doublons et conflits, recouvrement avec le SDK (y compris
  un appel et un échange scellés depuis l'attente, lecture 125), pièces trop
  grandes ou au-delà de la borne de temps, authentification et limitation,
  mode dégradé, URL jamais visitée, TLS de `otel.tls` avec un certificat
  généré par `openssl` et TLS 1.1 refusé, supervision) ;
- `enregistreur-sdk-vecteurs` : `pieces-modele/gemini-sdk-*` déclarés par le
  SDK JavaScript au démon : pièces, forme consolidée, `code.model`,
  `prompt_version`, `intent`, `is_error`, membres retirés, `context[0]` ;
- `enregistreur-sdk-exigences` : EX-6.1 à EX-6.8, EX-6.24, EX-7.7, EX-12.15,
  14.2, 14.5 et 14.6 pour le SDK, en réussite et en échec ; entrées hostiles
  sur la prise (JSON invalide, CR, lot, méthode ou paramètre inconnu,
  session ou appel d'une autre connexion, contexte d'une autre session,
  nombres non représentables, ligne trop longue, preuve d'identité fausse) ;
  prise TCP à jeton et en mTLS (autorité, certificats valide, expiré, d'une
  autre autorité, absent ou sans entrée, générés par `openssl`, lecture
  113) ; reprise à chaud (fermeture, connexion perdue, appel approuvé) et à
  froid, et la même reprise d'une lecture approuvée par les deux chemins
  (lecture 117) ;
- `enregistreur-sdk-client` : le SDK JavaScript, EX-6.9 à EX-6.15 (noms et
  valeurs rendues, connexion, délais, file des échanges, sortie du
  processus, erreurs, reprise de connexion, `Worker`, démon injoignable),
  contre le démon en processus et des démons simulés ;
- `enregistreur-sdk-parcours` : le démon réel `bin/noortrace`, le vrai
  service d'approbation et un agent Node.js réel qui emploie `noortrace-sdk`
  (contexte, lecture, écriture à intention durable avant exécution, refus,
  approbation par les votes EIP-191 des comptes de test déposés au canal de
  la console, échange de modèle déclaré, spans exportés par l'exportateur
  officiel OTLP/HTTP du SDK OpenTelemetry JavaScript et par un exportateur
  minimal en protobuf, fermeture avec un appel ouvert) ; journal vérifié par le noyau ; période
  close ; dossier d'un événement de chaque sorte vérifié par le noyau et par
  le binaire Go (en attente sans go1.27.3).

- `enregistreur-signataires-exigences` : classes A, B et C, backend par
  backend (tableau de la section « Signataires des classes A, B et C ») :
  cohérence classe/backend et refus de la classe D en production (EX-15.4
  pas 3), avertissement SoftHSM2 (lecture 181), fabrique, CRC32C, SigV4 ;
  PKCS#11 sur SoftHSM2 réel (deux formes de `CKA_EC_PARAMS`, trois préfixes
  de message, 16 000 octets, clé extractible, PIN faux, auxiliaire hostile :
  signature tronquée, d'un autre message, d'une autre clé, jamais rendue) ;
  Vault et OpenBao réels (jeton d'usage seul, version épinglée après une
  rotation interne, clé exportable ou d'un autre type refusée, service
  suspendu) ; AWS KMS et Google Cloud KMS simulés (requêtes exactes,
  service qui ment, lent, pré-hachage, CRC32C faux, autre version) ;
  enveloppes AWS par LocalStack réel (contexte faux, graine de 31 octets),
  TPM 2.0 par swtpm réel (PCR étendu : indescellable), Google et Azure
  simulés ; dans un cœur réel, pour chaque backend : `signer_ready` sans
  secret, appel signé, panne → mode « clé » et sortie (classes A et B),
  rotation, journal vérifié, effacement à l'arrêt ; refus de démarrage aux
  codes de §15 ; `health()` périodique ; références `{ "vault" }` contre
  Vault réel (KV version 2, jeton du backend ou `VAULT_ADDR`/`VAULT_TOKEN`,
  refus, démon réel) ; identités d'instance (IMDSv2, métadonnées de Compute
  Engine, serveurs simulés) ; comptes du rapprochement ; `noortrace-ctl cle
  rotation-urgence` sur le démon réel ;
- `enregistreur-signataires-parcours` : le démon réel `bin/noortrace` en
  développement avec la classe A (SoftHSM2), en production avec la classe B
  (Vault, OpenBao) et la classe C (LocalStack, swtpm) ; rotation planifiée
  en cours de route ; journal accepté par `N.verifierJournal`, dossiers
  d'avant et d'après la rotation valides pour le noyau et le binaire Go (en
  attente sans go1.27.3) ; ligne « clé indisponible » de la matrice de 14.2
  rejouée (Vault suspendu puis rétabli) ; TA-31 et TA-33 sont dans
  `test/adversarial.test.js` (`fixtures/enregistreur-signataires/ta.mjs`).
  Sans Docker,
  SoftHSM2, swtpm ou tpm2-tools, les tests concernés sont en attente, leur
  titre nomme la condition.

Les répertoires de test sont créés sous `os.tmpdir()`.

## Règle de salle blanche

Ce paquet et ses tests sont écrits d'après le seul texte de CT-2 (et des
passages de CT-1, CT-3, CT-7 qu'il cite), des schémas et des données des
vecteurs de `spec/vecteurs/ct-2`. Ni leur code ni leurs tests n'ouvrent, ne
cherchent ni n'importent `scripts/lib/**`, `scripts/vecteurs/**`,
`scripts/verify/**`, `test/enregistreur*.test.js` (hors
`test/enregistreur-coeur*`), `test/approbation.test.js`,
`test/journal.test.js`, les vérificateurs indépendants
(`spec/vecteurs/*/verificateur-independant/`) ni les répertoires
`confrontation/`.

## Dépendances

| Dépendance | Version | Usage |
|---|---|---|
| `@noortrace/noyau` | 0.1.0 (espace de travail) | formats et cryptographie de CT-1 |
| `node:crypto`, `node:fs`, `node:http` | Node.js ≥ 22 | PKCS#8, HMAC-SHA-256, AES-256-GCM (coffre), fichiers, supervision, canal du service |
| `node:vm`, `node:worker_threads` | Node.js ≥ 22 | borne de temps des motifs (EX-10.23), fils de calcul (EX-3.6) |
| `node:net`, `node:child_process`, `node:https`, `node:tls` | Node.js ≥ 22 | prises des connecteurs, serveurs d'outils stdio, Streamable HTTP et JWKS (frontal MCP) ; passerelle, connexions aux fournisseurs, serveur ICAP et ICAPS, prise du miroir (frontal modèle) |
| `node:zlib` | Node.js ≥ 22 | réponse de fournisseur comprimée malgré `Accept-Encoding: identity` (EX-5.9) |
| `node:crypto`, `node:http`, `node:https`, `node:net`, `node:tls` | Node.js ≥ 22 | lot WORM et haute disponibilité : signature SigV4, `Content-MD5`, accès S3, Azure et GCS ; protocole de PostgreSQL (SCRAM-SHA-256, MD5, TLS) et passerelle JSON d'etcd, écrits ici plutôt qu'une bibliothèque cliente |
| `node:http`, `node:https`, `node:zlib`, `node:net`, `node:tls` | Node.js ≥ 22 | lot SDK et OpenTelemetry : point d'entrée OTLP/HTTP (TLS), décompression gzip bornée, prise du point d'entrée SDK (Unix, TCP, TLS et mTLS) ; décodage protobuf écrit ici plutôt qu'une bibliothèque |

Le compagnon `noortrace-attributs` appelle les programmes `chattr` et
`lsattr` (e2fsprogs) : Node.js n'offre pas l'ioctl `FS_IOC_SETFLAGS` sans
module natif, et un module natif serait une dépendance compilée ; l'image
du compagnon (étape 7) doit les contenir. Les essais du compagnon
appellent aussi `setpriv` (util-linux).

Le magasin de bail `file` appelle le programme `flock` d'util-linux (essayé
avec la version 2.39.3, `flock --exclusive --nonblock --conflict-exit-code`)
et `/bin/sh` : Node.js n'offre pas l'appel `flock(2)` sans module natif, et
le texte prescrit ce verrou (13.2, lecture 148) ; l'image du démon doit
contenir util-linux. Sans lui, l'acquisition du bail `file` est refusée.

Le signataire de classe A lance `python3` (3.8 ou plus, bibliothèque
standard seule : `ctypes`, essayé avec Python 3.12) pour l'auxiliaire
PKCS#11 (lecture 174) ; l'enveloppe TPM 2.0 appelle `tpm2_createprimary`,
`tpm2_load`, `tpm2_unseal` et `tpm2_flushcontext` de tpm2-tools (essayé
avec la version 5.6). Les classes B et C parlent HTTP(S) avec `node:http`,
`node:https` et `node:crypto` (SigV4, JWT RS256, CRC32C écrits ici plutôt
qu'un kit de fournisseur). Pour les essais seulement : SoftHSM2 (2.6.1),
swtpm (0.7.3), et les images Vault 1.20.4, OpenBao 2.4.3 et LocalStack
4.0.3 épinglées par condensé.

Aucune autre dépendance d'exécution. Le SDK JavaScript `noortrace-sdk`
n'en a aucune (`node:net`, `node:tls`, `node:fs`). Pour les essais
seulement, la racine du dépôt a en `devDependencies`, versions exactes,
l'exportateur officiel OTLP/HTTP du SDK OpenTelemetry JavaScript :
`@opentelemetry/exporter-trace-otlp-http` 0.223.0,
`@opentelemetry/sdk-trace-base` 2.12.0 et `@opentelemetry/api` 1.9.1
(versions publiées ensemble le 2026-10-06 ; `api` borné à `<1.10.0` par
`sdk-trace-base`). Raison : le parcours de bout en bout montre que le point
d'entrée OTLP/HTTP du démon accepte ce qu'émet le SDK officiel, et pas
seulement des lots écrits par les essais.
