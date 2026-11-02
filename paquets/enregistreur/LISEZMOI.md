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

Les frontaux SDK et OpenTelemetry, le WORM, la haute disponibilité et
l'ancrage sont des lots suivants : [INTERFACES.md](INTERFACES.md) est leur
contrat. La rédaction avant hachage (§10), le frontal MCP (§4), le moteur
de politique (§7.5, 14.2, 14.6) et le frontal modèle (§5) sont faits
(sections « Rédaction avant hachage », « Frontal MCP », « Moteur de
politique » et « Frontal modèle » ci-dessous).

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

## Démarrer le démon

```sh
noortrace validate-config configuration.json    # pas 1 à 3 d'EX-15.4 ; code 0 ou 2
noortrace --config configuration.json           # démarre ; SIGTERM, SIGINT : arrêt propre ; SIGHUP : rechargement
```

Avec `mcp.enabled`, le démon démarre ensuite le frontal MCP : serveurs
d'outils stdio lancés et listés, prise `mcp.socket` des connecteurs, prise
`mcp.connector_tcp` et Streamable HTTP `mcp.http` s'ils sont configurés.
L'hôte lance le connecteur comme serveur MCP stdio (19.5.1) :

```sh
noortrace-connecteur --socket /run/noortrace/mcp.sock
```

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
observation (EX-15.8), approbateurs de test.

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

Hors du répertoire du journal : le verrou du bail (`lease.store.path`) et
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
| `coeur.mjs`, `cli.mjs`, `bin/noortrace` | assemblage, démarrage, démon | §3, §15.4, §15.6 |

## Ce qui relève des lots suivants

Part du frontal modèle non faite : réassemblage HTTP/2 de la copie du
miroir (EX-5.6 : non couvert par la version 0, section 21) ; traducteurs des
formats de copie des équipements réels vers les trames de l'adaptateur
(lecture 79) ; entrée `echangeModele` du SDK (lot suivant, qui reprend la
dérivation et le registre de `src/modele/`) ;
SDK, adaptateurs et ingestion OpenTelemetry (§6) ; vrai service
d'approbation (CT-3, paquet `@noortrace/approbation`) ; notifications de
progression pendant une rétention (EX-4.50, CT-3 EX-11.6, facultatives) ; part du
frontal MCP non faite : relais hors chaîne de 4.5 (`resources/*`,
`prompts/*`, `completion/complete` : `-32601`), requêtes du serveur vers le
client et `sampling` en échange de modèle (4.6, EX-4.29 : refusées par
`-32601` côté serveur hérité, `inputRequests` non déclarées refusées par
`-31016`), continuation MRTR d'un appel approuvé (EX-4.21 : la ré-émission
repasse par le pas 3, échec fermé), client OAuth vers un serveur d'outils
(EX-4.40, EX-4.42 : refusé à la connexion), mTLS et TLS de la prise TCP des
connecteurs, `prctl(PR_SET_DUMPABLE)` (EX-3.5, sans module natif) ;
signataires des classes A, B et C ; magasins de
bail `postgresql` et `etcd`, attente du bail, bascule (§13) ; copies WORM,
registre des copies, contrôle du verrou, relevé, gel juridique (§12.6,
§12.11) ; purge des pièces (EX-12.20) ; attribut append-only (EX-12.18) ;
ancrage (CT-5) et registre (CT-4) ; exportateur complet de CT-6 ; contrôles
périodiques de la supervision (EX-17.5) ; démonstration (§19).

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
```

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
- `enregistreur-modele-securite` : quotas d'EX-4.47 sur la passerelle
  (requêtes en cours, octets reçus, octets de pièces, temps de capture,
  mode observation), jeton OAuth d'EX-5.8 point 2 (valide, refusé pour
  chaque cause, configuration refusée au démarrage), TLS de `model.tls` avec
  des certificats générés à l'exécution par `openssl` (poignée de main,
  autorité inconnue, nom faux, TLS 1.1 refusé face à un témoin qui
  l'accepte, certificat illisible : démarrage refusé).

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

Aucune autre dépendance d'exécution.
