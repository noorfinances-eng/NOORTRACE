# Serveur de console (`src/serveur/`, `bin/noortrace-console`)

Serveur HTTPS de la console d'exploitation, sans cadriciel (`node:http`,
`node:https`, `node:crypto`), tel que le fixent CT-3 13.20 et 13.21
(EX-13.43 à EX-13.49), EX-10.13, EX-13.8, EX-13.35 et le contrat
`../../INTERFACES.md`, sections 0 et 2. Étape 6.

Importations : `node:*` ; de `@noortrace/approbation`, `RegistreSchemas` et
`lireJsonStrict` seulement ; de la bibliothèque (`@noortrace/console`),
`estIdentiteCanonique`, `METHODES_CANAL` et `METHODES_REAUTHENTIFICATION`,
importée au démarrage (`import()` dans `demarrerServeur`), de sorte que la
validation et la sonde n'en dépendent pas.

Fichiers repris de noorchain-core : aucun. Le jeton de session signé et la
garde d'hôte de 13.1 sont écrits d'après le texte de CT-3, sans lecture du
code de curators-hub.

## Modules

| Module | Rôle |
|---|---|
| `index.mjs` | `demarrerServeur`, `validerConfiguration`, `sonder`, `principal` (contrat 2.2) |
| `cli.mjs` | ligne de commande (2.1) |
| `configuration.mjs` | schémas embarqués (`../../schemas/`), rapport d'EX-10.13, défauts, références de secrets |
| `serveur.mjs` | écoute HTTPS, ordre de 2.5, en-têtes de 2.6, routes, relais, santé |
| `sessions.mjs` | sessions en mémoire, cookie de session (HMAC-SHA256), cookie de transaction (AES-256-GCM), `tid` présentés |
| `oidc.mjs` | découverte et jeu de clés, demande par code avec PKCE, échange, vérification du jeton (EX-13.46) |
| `local.mjs` | système local : scrypt, deux calculs au plus, verrou progressif |
| `service.mjs` | client du canal de la console (relais, `GET /v0/etat`) |
| `pages.mjs` | manifeste des pages, empreintes vérifiées au démarrage |
| `sonde.mjs` | sonde d'EX-13.44 |
| `outils.mjs` | base64url, instants, temps constant, journal, `retour` retenu |

## Lectures du texte (choix de l'étape 6)

Chacune est aussi une question du rapport de l'étape quand le texte ne la
tranche pas.

- **Chemins selon le système d'identité.** Avec OIDC, `/connexion/locale`
  n'existe pas ; avec le système local, `/connexion/retour` n'existe pas :
  404 `requete_invalide` à l'étape 4 de 2.5, quelle que soit la méthode.
- **Page d'erreur HTML.** Toute erreur rendue sur `GET` ou `HEAD` de
  `/connexion` et `/connexion/retour` (y compris 421 et le 404 du système
  local) est la page d'erreur de 2.6 ; partout ailleurs, `$defs/erreur`.
- **Corps.** Un corps annoncé sur une route `GET` doit être du JSON strict
  (étape 6) ; `/deconnexion` n'admet que le corps vide ou `{}`.
- **Relais.** Les octets du corps reçu sont relayés tels quels :
  `session_identity` est remplacé à sa place s'il est au premier niveau,
  ajouté à la fin sinon ; aucun autre octet ne change (nombres, blancs,
  échappements compris).
- **Découverte.** Un document refusé par le point 1 d'EX-13.45 (`issuer`
  différent, point non `https`), illisible, d'un statut autre que 200, d'une
  redirection, de plus de 1 048 576 octets, ou un jeu de clés illisible, est
  une lecture en échec : faute de copie valable, `fournisseur_indisponible`.
  Un document qui annonce des méthodes PKCE sans `S256`, ou
  `token_endpoint_auth_methods_supported` sans `client_secret_basic` (ou un
  membre qui n'est pas un tableau), est gardé, les connexions sont refusées
  `fournisseur_erreur` dès `GET /connexion`, et `identity_ready` est faux
  (CT-3 0.6, EX-13.44 : une santé « prête » qui refuse chaque connexion
  serait fausse).
- **Magasin du système.** Sans `service.ca`, et sans agent d'essai, les
  requêtes HTTPS vers le service et vers le fournisseur OIDC portent
  explicitement `ca` = `tls.getCACertificates("system")` : le magasin du
  système, non la liste intégrée de Node (EX-13.42, EX-13.45).
- **Point de jeton.** Statut autre que 200, corps hors JSON strict, sans
  `id_token` de type chaîne, ou de plus de 1 048 576 octets :
  `fournisseur_erreur` ; aucune réponse (délai, réseau, TLS) :
  `fournisseur_indisponible`. Un retour sans `code` ni `error` :
  `fournisseur_erreur`.
- **Transaction.** `tid`, `state` et `nonce` : 16 octets tirés au hasard,
  en base64url ; `created_at` en millisecondes ; `sid` en hexadécimal. La
  transaction est consommée dès qu'un cookie se déchiffre, date de moins de
  600 s et porte un `tid` nouveau, même si `state` est faux ou absent.
- **Clé du jeton (point 2).** Avec `kid`, les clés de ce `kid` ; sans, toutes
  les clés ; parmi elles, exactement une clé compatible, sinon le jeton est
  invalide.
- **Encodage de `client_secret_basic`.** HTML 4.01 au sens strict de
  l'annexe B de la RFC 6749 : seuls les caractères alphanumériques ASCII
  restent tels quels, l'espace devient `+`, tout autre octet UTF-8 `%XX`.
- **Boucle locale (`tls_exige`).** `127.0.0.1`, `[::1]` et `localhost`
  écrits tels quels dans `service.url` ; `127.1` ou `LOCALHOST` ne le sont
  pas.
- **Références.** Jeton et secret du client privés de leurs blancs ASCII de
  tête et de fin ; secret du client vide ou en UTF-8 invalide : mal formé ;
  clé TLS qui ne va pas avec le certificat : `/tls/key` mal formée ;
  `service.url` conforme au motif du schéma mais non analysable, ou de port
  hors de 1 à 65 535 : règle `url_illisible` de la validation (CT-3 0.6) ;
  `console_origin` au port 443 écrit : règle `origine_port_par_defaut`.
- **Refus au démarrage (EX-10.14).** Une ligne `$defs/rapport_validation`
  sur la sortie d'erreur, code 1 : `reference_illisible` (référence
  illisible ou mal formée, au pointeur de la référence), `ecoute_impossible`
  (`/listen`), `parcours_non_offert` (`/walletconnect`) ; un manifeste des
  pages en écart est écrit comme texte.
- **Système local.** Un compte dont l'identité `utilisateur <domain> <name>`
  n'est pas canonique (plus de 256 caractères) fait refuser le démarrage
  (`reference_illisible`, `/identity/accounts`). L'instant d'un échec est celui de la vérification ;
  un succès oublie le compteur du nom ; « le plus ancien » des noms suivis est
  celui dont le compteur a changé le moins récemment.
- **`reauth_max_age_s` = 0.** Une méthode de la liste d'EX-13.8 est tenue
  pour relayée dès son envoi au service, quelle que soit la réponse. Quand
  la première est `preparer_inscription`, l'authentification couvre aussi la
  première `inscrire` relayée ensuite dans les 600 s, et elle seule (CT-3
  0.6, EX-13.48, point 5).
- **Rôle.** L'appel `annuaire` qui suit l'ouverture d'une session est attendu
  (au plus `service_timeout_ms`) avant la réponse de connexion ; une réponse
  `annuaire` autre que 200 laisse le rôle inchangé.
- **Manifeste.** Racine du paquet `@noortrace/console` : `<pages>/../..`
  (`src/pages/` par défaut, donc la racine du paquet) ; `carte_sha256`
  recalculé sur `carte` ; types admis : `text/css`, `text/javascript`,
  `application/json` (`; charset=utf-8`) ; chemins sous `/statique/`, sources
  sans remontée.
- **Santé.** Une seule lecture de `GET /v0/etat` à la fois, résultat gardé
  5 s depuis sa fin ; forme d'EX-12.12 exacte (trois membres).
- **Requête que l'analyseur de Node refuse** (longueur illisible, en-têtes
  contradictoires) : 400 `requete_invalide` sous les en-têtes de 2.6 ; délai
  de requête dépassé : connexion fermée. Erreur de programmation : 500 sans
  corps, sous les mêmes en-têtes.
- **Sonde.** Pas d'indication de nom si l'hôte de `console_origin` est une
  adresse IP ; corps écrit sur une ligne (fins de ligne remplacées par une
  espace) ; arguments incorrects : code 1 (EX-13.44 : codes 0 et 1
  seulement ; CT-3 0.6, 15.2).
- **Journal.** `serveur_pret` porte `ecoute` (`host`, `port`) ;
  `serveur_arrete`, rien ; `session_fermee`, `cause` seulement ; l'instant
  `ts` vient de l'horloge du serveur (injectée par les essais).

## Essais

`test/exploitation-console-serveur-configuration.test.js`,
`test/exploitation-console-serveur-http.test.js` (TE-20),
`test/exploitation-console-serveur-oidc.test.js` (TI-22, TA-100) ; outils
sous `test/fixtures/exploitation-console/` (`fournisseur-oidc.mjs`,
`service.mjs`, `serveur/`). Mis en attente sans `openssl`.
