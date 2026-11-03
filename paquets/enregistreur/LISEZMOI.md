# @noortrace/enregistreur

Cœur du démon `noortrace`, premier lot de l'étape 4 de la phase 2 : tout ce
qui transforme une capture en événement CT-1 scellé et durable, et la
clôture des périodes, tels que les fixe la spécification normative
[CT-2 version 0.6](../../spec/CT-2-enregistreur.md) (sections 3, 7, 8, 9, 11,
12, 14, 15, 17, annexes A et B), avec [CT-1](../../spec/CT-1-evenements-et-formats.md)
pour les formats et [CT-3](../../spec/CT-3-approbations.md) §12 pour
l'interface du service d'approbation.

Le paquet est écrit à neuf depuis le seul texte de la spécification. Il
importe la bibliothèque noyau [`@noortrace/noyau`](../noyau/LISEZMOI.md) pour
tout ce qu'elle fait (JCS v0, hachage, Ed25519, EIP-191, événement, rotation,
Merkle, manifeste, point de contrôle, dossier, schémas de CT-1) et ne le
réécrit pas. Les vecteurs de `spec/vecteurs/ct-2` et l'annexe A sont le juge.

L'ancrage, le SDK Python et les adaptateurs de cadres sont des lots
suivants : [INTERFACES.md](INTERFACES.md) est leur contrat. La rédaction avant
hachage (§10), le frontal MCP (§4), le moteur de politique (§7.5, 14.2, 14.6),
le frontal modèle (§5), le WORM, le gel juridique et la haute disponibilité
(§12.6, §12.11, §13), le point d'entrée SDK, le SDK JavaScript et l'ingestion
OpenTelemetry (§6) sont faits (sections « Rédaction avant hachage »,
« Frontal MCP », « Moteur de politique », « Frontal modèle », « WORM, gel
juridique et haute disponibilité » et « SDK et ingestion OpenTelemetry »
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
  politique exigée (EX-9.1), pièces exigées sur disque (EX-8.9), signature
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
  non), refusée en production (EX-11.8) ; rotation (EX-11.15).
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
  l'écrivain, de la clé, du bail, du mode dégradé.
- **Export d'un dossier minimal** (CT-1 §11) : douze parties v0 (réservées
  absentes, « hors périmètre CT-1 ») et la treizième, `points-de-controle.json`.

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
- **Supervision** (EX-17.5 à EX-17.7) : contrôles horaires (manifeste,
  signature, continuité, SHA-256 de chaque copie de l'heure, signataire),
  quotidiens (relecture complète des segments copiés dans la journée,
  rétention par défaut du support, registre des gels et état `on` des
  versions des gels actifs), relevé de verrouillage tous les
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
  supérieure (EX-13.5 (1)) ; un démon qui perd son bail se relance et
  redevient passif (13.4 pas 8).

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
```

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
<cause>`, code 2.

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
`approval` pour SG-4, SG-7, RL-4, EX-9.4, `failure.pending_max_events`).

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

Hors du répertoire du journal : la table ou la clé du magasin de bail
`postgresql` ou `etcd` (13.2), le verrou du bail `file` (`lease.store.path`) et
son époque (`<path>.epoch`), le journal d'exploitation
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
| `signataires.mjs` | signataires (interface, classe D) | §11 |
| `bail.mjs` | bail (interface, magasin `file`) | §13 (part du cœur) |
| `lui-meme.mjs` | journal sur lui-même | §9.1 |
| `journal-exploitation.mjs` | journal d'exploitation | §9.2, §17.3 |
| `supervision.mjs`, `degrade.mjs`, `horloge.mjs` | supervision, mode dégradé, horloge | §17, §14, §7.4 |
| `approbations.mjs`, `service-approbation-http.mjs`, `service-approbation-factice.mjs` | interface du service d'approbation | §7.5, §12.9, CT-3 §12 |
| `ancrage.mjs`, `worm.mjs` | remise à l'ancrage, copies WORM (interfaces) | §12.10, §12.6 |
| `dossier.mjs` | export d'un dossier minimal | CT-1 §11 |
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
(lecture 79) ; SDK Python et adaptateurs de cadres (6.4, 6.6 ; le
protocole de 6.2 et la file d'EX-6.11 (3) sont prêts) ; part du lot SDK et
OpenTelemetry non faite : OTLP/gRPC (non servi en version 0, EX-6.26) ; notifications de
progression pendant une rétention (EX-4.50, CT-3 EX-11.6, facultatives) ; part du
frontal MCP non faite : relais hors chaîne de 4.5 (`resources/*`,
`prompts/*`, `completion/complete` : `-32601`), requêtes du serveur vers le
client et `sampling` en échange de modèle (4.6, EX-4.29 : refusées par
`-32601` côté serveur hérité, `inputRequests` non déclarées refusées par
`-31016`), continuation MRTR d'un appel approuvé (EX-4.21 : la ré-émission
repasse par le pas 3, échec fermé), client OAuth vers un serveur d'outils
(EX-4.40, EX-4.42 : refusé à la connexion), `prctl(PR_SET_DUMPABLE)` (EX-3.5, sans module natif) ;
signataires des classes A, B et C ; purge des pièces (EX-12.20, et donc sa
suspension pendant un gel) ; image `noortrace/attributs` du compagnon
(étape 7 : le programme `noortrace-attributs` est prêt) ; procès-verbal
`restauration` de CT-8 (11.9) ; part du lot WORM non faite : copie, liste des
versions, lecture et écriture d'un objet sur Azure et Google Cloud Storage,
que CT-2 0.5 ne fixe pas (lecture 84), et donc le gel sur ces supports
au-delà des requêtes de gel et de lecture d'état ; ancrage (CT-5) et
registre (CT-4) ; exportateur complet de CT-6 ; démonstration (§19).

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
6. **Magasin de bail `file`** (13.2 : `flock(LOCK_EX | LOCK_NB)`). Node.js
   n'offre pas `flock(2)` sans module natif : le verrou est un fichier créé en
   exclusion qui porte le PID du détenteur, repris quand ce processus n'est
   plus vivant (arrêt brutal) ; l'époque est `<path>.epoch`, incrémentée et
   forcée sur disque à chaque acquisition. Un bail perdu exige un redémarrage
   (EX-13.6 interdit la reprise « à chaud » sans relecture).
7. **Clé suivante de classe D.** 15.1 nomme `signer.rotation.next_key_id` sans
   dire où est son fichier. Lecture : même répertoire que
   `signer.backend.path`, nom `<next_key_id>` suivi de l'extension du fichier
   courant ; même phrase de passe.
8. **Signature de test** (EX-15.4 pas 5, EX-14.11) et EX-11.18 (« aucun autre
   message n'est jamais soumis au signataire »). Lecture : le message de test
   est `P_S` seul, de la forme `P_S ‖ C` avec `C` vide, qu'aucun événement ne
   peut produire (sa forme canonique n'est jamais vide).
9. **Signature d'une clé dont la clé publique est inconnue à la relecture.**
   EX-12.10 pas 2 exige une `sig` qui vérifie « sous la clé en vigueur ». La
   clé initiale n'est pas dans la chaîne ; si le signataire ne la détient
   plus, sa clé publique manque. Lecture : la signature n'est alors pas
   vérifiée à la relecture (hash, `seq`, `prev_hash` le sont) ; une clé
   connue qui ne vérifie pas est une corruption.
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
    connecteurs (bit collant recommandé).

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
    `objet_present_different`). Le composant d'ancrage n'est pas encore dans
    ce paquet.
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

## Tests

Depuis la racine du dépôt, après `npm ci` :

```sh
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-annexe-a.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-journal.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-reprise.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-config.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-coeur-approbations.test.js
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
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-miroir.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-securite.test.js
NOORTRACE_GO_BIN=<répertoire de go1.27.3> npx hardhat --config hardhat.config.mjs test test/enregistreur-modele-parcours.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-vecteurs.test.js
npx hardhat --config hardhat.config.mjs test test/enregistreur-worm-exigences.test.js
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
  MAC différente, fourche, règles de configuration ;
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
