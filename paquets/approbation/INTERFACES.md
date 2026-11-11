# Interfaces du service d'approbation

Ce document s'adresse à ceux qui raccordent le service : le démon
`noortrace` (lot moteur de politique, rubrique d de
`paquets/enregistreur/INTERFACES.md`) et la console de l'étape 6 (CT-3 §13,
canal de 12.9). Avec CT-3 et `ticket-v0`, il suffit.

## a) Canal du noyau (CT-3 12.1 à 12.8)

Le démon joint le service par `ClientServiceApprobation` de
`@noortrace/enregistreur`, réglé par `policy.approval.service` :

```js
new ClientServiceApprobation({ socket: "/run/noortrace/approbation.sock", jeton, timeout_ms })   // ou { url: "https://…" }
```

`jeton` est la valeur du secret de `policy.approval.service.token`, et le
fichier ou la variable `noyau.token` de la configuration du service. Chaque
méthode est `POST <base>/v0/<méthode>`, corps et réponse objets JSON stricts
(clé inconnue : `requete_invalide`). Erreur : HTTP 4xx ou 5xx, corps
`{ "error": { "code", "message", "data" } }`, `code` de la table 12.8 ;
authentification refusée : 401, `requete_invalide`.

| Méthode | Requête | Réponse | Erreurs propres |
|---|---|---|---|
| `charger` | `{ org_id, journal_id, environment, policy_version, policy_sha256, approval: { rules, mode, hold_timeout_ms, expire_after_ms, timeout_ms }, tools, requesters }` (sans `service`) | `{ policy_version, policy_sha256, approval_candidates }` (triés) | `politique_invalide` (`data.errors`, toutes, triées), `requete_invalide` (autre journal, version déjà chargée sous une autre empreinte) |
| `evaluer` | `$defs/requete_evaluer` (CT-2 EX-7.4) ; `intent` chaîne ou `null` | les six membres de 12.3 ; sept combinaisons d'EX-7.16, ou celle d'EX-12.20 en observation | `non_pret`, `politique_inconnue`, `plafond_atteint` |
| `ouvrir` | `{ ticket, request_hash, request_seq, request_ts, request_event, arguments_piece }` | `{ ticket, state, deadline }` | `ticket_inconnu`, `ticket_deja_ouvert` (`data.request_hash`), `requete_invalide` (événement ou pièce qui ne correspond pas, `request_ts` futur) |
| `decisions` | `{ wait_ms }` (0 à 25 000) | `{ remises: [ $defs/remise ] }`, au plus une par ticket, dans l'ordre de calcul | — |
| `acquitter` | `{ remise_id, ticket, result, reason, seq, hash, at, decision, held, approval }` | `{ ticket, state }` | `requete_invalide` (remise inconnue, données différentes d'une décision scellée) |
| `consommer` | `{ ticket, seq, hash }` | `{ ticket, state: "consomme" }` ou `"clos"` (T22) | `requete_invalide`, `ticket_inconnu` (finales, CT-2 EX-7.20) |
| `expiration` | `{ ticket, seq, hash, at, approval }` | `{ ticket, state: "expire" }` | `requete_invalide` |
| `GET /v0/etat` | — | `{ ready, set_read_at, open_tickets }` (EX-12.12) | — |

Comportements sur lesquels le démon peut compter :

- chaque réponse suit la persistance de son effet (EX-7.22) ; `evaluer`,
  `ouvrir`, `acquitter`, `consommer`, `expiration` répétés à l'identique sont
  idempotents (EX-7.20) ; une remise livrée et non acquittée est
  re-présentée après `remise_representation_ms` (30 s par défaut), après
  `timeout_ms` de la version pour un `temporaire` (T12), et aussitôt après un
  redémarrage ;
- l'objet `approval` rendu à une ré-émission est celui reçu par `acquitter`
  ou `expiration`, tel quel (`sealed.approval`) ;
- le service vérifie lui-même chaque remise par SG-1 à SG-7 avant de la
  livrer et consigne un écart (`remise_non_conforme`) ;
- l'`approver_set` d'une réponse `nouveau` est exploitable (EX-12.6) :
  jeu statique, ou jeu de repli avec ` repli`.

## b) Canal de la console (CT-3 12.9), part de l'étape 4

Écoute distincte (`console` de la configuration), jeton distinct. Méthodes
servies : `voter`, `recuser`, `retirer`, aux corps de 7.4 (`session_identity`
obligatoire, forme canonique d'EX-13.7, sinon `identite_invalide`). Le
contrôle de l'identité de session (`controleCanal`, EX-12.14, EX-12.16,
EX-12.19) se fait sur l'annuaire lu (`console.annuaire`) avant de former
l'entrée ; un refus ne laisse aucune trace dans le ticket. Réponse
`{ ticket, state }` ; un vote refusé reçoit la raison d'EX-9.10. Les méthodes
du noyau y sont refusées (`requete_invalide`, EX-12.13), et réciproquement.

Non servies à l'étape 4 (`requete_invalide`, message « non servie a l'etape
4 ») : `tickets`, `consulter`, `annuaire`, `preparer_inscription`,
`inscrire`, `valider`, `revoquer`, `desactiver`, `reactiver`,
`lier_demandeur`, `delier_demandeur`.

## c) Pour l'étape 6

```js
import {
  demarrerService, ServiceApprobation, Machine, Annuaire, controleCanal, identiteCanonique,
  condenseA, objetA, normaliserSignature, adresseDuVote, verifierRemise, evaluer, candidats,
  validerPolitique, avertissementsPolitique, registreSchemas, IDS,
} from "@noortrace/approbation";

const inst = await demarrerService({ config, secrets, base, horloge, appelRpc, sortie });
inst.service.machine.tickets          // Map id → document ticket-v0 (lecture seule)
inst.service.machine.version(pv)      // version chargée : approval.rules (politique), tools (gabarits d'effets)
inst.service.console(methode, corps)  // voter, recuser, retirer (contrôle du canal compris)
inst.service.supervision.ecouteurs.add((notification) => …)   // canaux de notification
inst.service.tic()                    // déclenche les minuteurs échus (horloge du service)
await inst.arreter()
```

- **Vue du ticket** (`consulter`, EX-12.14) : `request` (outil, arguments,
  délégation, version) et `request.retained_event`, `request.arguments_piece`
  sont dans le document du ticket tant qu'il est actif ; `intent` n'est pas
  un membre de `ticket-v0` : la vue le prend de `retained_event.intent` (une
  chaîne, ou une référence, `intent_status`) ; `rule`, `opening`,
  `approver_set`, `effective_required`, `eligible`, `votes`, `contest_end`,
  `deadline` aussi ; les membres ajoutés sont dans les données des
  transitions `jeu_lu` (`added_members`) ; `digests` : `condenseA({ decision,
  ticket, request_hash, org_id, journal_id })` ; `effects` : les gabarits de
  `version(pv).tools[].effects`, à évaluer selon CT-2 EX-7.6.
- **Notifications** (`notifications.ndjson` et écouteurs) : `{ ts, kind,
  ticket, tool?, deadline?, approvers?, notify?, requester?, decision?,
  approver?, digest?, at?, link }` ; `kind` ∈ `ouverture`, `escalade`,
  `membres_ajoutes`, `vote_inscrit`.
- **Persistance** (relecture C) : `MagasinEtat.ajouter` n'écrit pas les
  arguments en clair dans le journal (fichiers `etat/arguments/`, effacés au
  passage en état terminal, EX-7.24) ; après un échec d'écriture,
  `magasin.enPanne` est vrai et seul `magasin.reprendre(machine.exporter())`
  (état complet) rouvre les ajouts ; une entrée sans effet n'écrit rien.
  `machine.entree({ kind: "jeu_lu", … }, { lecture: { debut, cible } })` :
  instant du début de la lecture (EX-8.7) et jeu épinglé lu (EX-8.1) ; sans
  `lecture`, comportement des traces de l'annexe A.6.
- **Annuaire** : `Annuaire` est en lecture ; les opérations (13.6), leur
  persistance (EX-12.17) et la recopie des administrateurs (EX-13.37) sont à
  ajouter ; `controleCanal` sert déjà les cinq méthodes contrôlées.

## d) Configuration et ligne de commande

Voir `LISEZMOI.md` (configuration, fichiers sur disque, lectures).
`noortrace-approbation --config <fichier>` écrit
`{"pret":true,"pid","noyau","console"}` sur la sortie standard quand il
écoute ; SIGTERM l'arrête proprement.

## e) Étape 6 : canal de la console complet, annuaire persisté, notifications, configuration (CT-3 révision 0.5)

État : **à faire (étape 6)**, sauf mention contraire. Cette rubrique fixe ce
que le service sert à la console d'exploitation (`@noortrace/console`,
`paquets/console/INTERFACES.md`) ; elle remplace, une fois livrée, la liste
des méthodes non servies de la rubrique b) et, dans la rubrique c), la forme
des notifications et la lecture de l'annuaire. Règles : CT-3 7.10 (EX-7.30),
10.3 (EX-10.10 à EX-10.13), 12.7 (EX-12.12), 12.9 (EX-12.13 à EX-12.21),
13.3 à 13.8 (EX-13.7 à EX-13.19, EX-13.37, EX-13.38), 13.19 (EX-13.39 à
EX-13.42).

### e.1 Module d'annuaire importé

Les règles de l'annuaire ont une seule implémentation, celle de
`@noortrace/console/annuaire` (rubrique 1.3 de
`paquets/console/INTERFACES.md`) : `estIdentiteCanonique`, `annuaireVide`,
`entreeActive`, `adresseActive`, `sessionDeLOrganisation`, `adressesConnues`,
`annuaireDeSession`, `verifierInscription`, `appliquerOperation`,
`defisNonExpires`, `recopierAdministrateurs`, `controleCanal`,
`verifierAnnuaireExporte`. `src/annuaire.mjs` n'en garde aucune copie : le
prédicat `identiteCanonique`, la classe `Annuaire` et `controleCanal` de
l'étape 4 sont retirés au profit de ces imports (le paquet dépend déjà de
`@noortrace/console`). Le service garde l'état de l'annuaire (document
courant, défis non expirés) et sa persistance, sans réécrire aucune règle.

### e.2 Méthodes du canal de la console (EX-12.13)

Sur l'écoute `console`, et sur elle seule, `POST <base>/v0/<méthode>` ;
`session_identity` non nulle et canonique (`identite_invalide` juste après
la forme du corps) ; méthodes du noyau refusées (`requete_invalide`) :

| Méthode | Requête (`$defs`) | Réponse | Ordre des refus | État |
|---|---|---|---|---|
| `tickets` | `requete_tickets` (`console-service-v0`) | `reponse_tickets`, avec `contest_ms` et `contest` sur chaque ticket ; avec `related_to`, `related` (au plus 20, `refuse` ou `expire`, même `launched_by` et même `tool_announced`, scellés depuis moins de l'`expire_after_ms` du ticket `related_to`, tri par `sealed.approval.at` décroissant puis par identifiant) | point 1 d'EX-12.14 ; avec `related_to`, l'ordre de `consulter` appliqué au ticket désigné (`controleCanal(…, "consulter", …)`), puis `ticket_non_ouvert` | à faire |
| `consulter` | `requete_consulter` (`console-approbation-v0`) | `vue_ticket` (EX-12.14, EX-12.15 : `request`, `retained_event`, `arguments_piece`, `rule`, `opening`, `effects` évalués avec `unresolved`, `deadline`, `contest`, `approver_set`, `effective_required`, `added_members`, `eligible`, `votes`, `separation` avec `requester_directory_addresses`, `digests`) | EX-12.14, points 1 à 3, puis `ticket_non_ouvert` | à faire |
| `voter`, `recuser`, `retirer` | données des entrées de 7.4 | `reponse_voter`, `reponse_etat` | EX-12.16, EX-12.19, puis EX-9.10 et T10 | fait (étape 4) ; notification `vote_inscrit` à faire (e.4) |
| `annuaire` | `requete_annuaire` | `annuaireDeSession` | forme, identité | à faire |
| `preparer_inscription` | `requete_preparer_inscription` | `reponse_preparer_inscription` | EX-13.13 | à faire |
| `inscrire` | `requete_inscrire` | `reponse_adresse` | EX-13.15, pas 1 à 13 | à faire |
| `valider`, `revoquer` | `requete_valider`, `requete_revoquer` | `reponse_adresse` | EX-13.17 | à faire |
| `desactiver`, `reactiver` | `requete_entree` | `reponse_entree` | EX-13.17 | à faire |
| `lier_demandeur`, `delier_demandeur` | `requete_demandeur` | `reponse_entree` | EX-13.17 | à faire |
| `GET /v0/etat` | — | `{ ready, set_read_at, open_tickets }` | authentifié comme le canal (EX-12.12) ; aussi sur l'écoute `etat`, sans authentification | à faire sur le canal de la console |

Statut HTTP d'une erreur (étend la lecture 20 de `LISEZMOI.md`) : 400
`requete_invalide`, `identite_invalide`, `message_invalide` ; 403
`session_non_autorisee`, `non_administrateur`, `auto_validation`,
`revocation_non_autorisee` ; 404 `ticket_inconnu`, `entree_inconnue`,
`adresse_inconnue`, `nonce_inconnu`, `demandeur_inconnu` ; 409 toute autre
raison qui refuse une entrée de ticket ou une opération de l'annuaire
(`ticket_non_ouvert`, `ticket_clos_aux_votes`, `jeu_non_fige`,
`signature_invalide`, `hors_jeu`, `auto_approbation`, `recuse`,
`motif_trop_long`, `vote_identique`, `retrait_non_autorise`,
`nonce_deja_utilise`, `inscription_expiree`, `origine_differente`,
`organisation_differente`, `identite_differente`, `adresse_differente`,
`identite_desactivee`, `adresse_deja_attribuee`, `etat_incompatible`,
`demandeur_deja_lie`) ; 429 `plafond_atteint` ; 503 `non_pret`. La console
ne s'appuie que sur `error.code`.

Chaque méthode qui modifie l'annuaire, et `preparer_inscription` pour son
défi, est persistée avec `fsync` avant sa réponse (EX-12.17) ; une opération
refusée ne change rien et est consignée au journal du service avec sa raison
(`operation_annuaire_refusee`). Aucune opération de l'annuaire ne touche un
ticket (EX-12.18).

### e.3 Annuaire persisté (EX-13.38, EX-7.30)

- L'annuaire et ses défis non expirés sont des membres des enregistrements
  chiffrés de l'état (`etat/journal.ndjson`, `etat/instantane.chiffre`,
  nature `ligne` et `instantane`, EX-7.30) : `annuaire` (document
  `annuaire-approbateurs-v0`) et `defis` (tableau de `$defs/defi`), écrits
  en entier à chaque changement, relus à la reprise (EX-7.23).
- Préséance au démarrage, dans l'ordre d'EX-13.38 : état persisté ; sinon
  `console.annuaire` (document conforme et sans écart aux points 1 à 6
  d'EX-13.19, `verifierAnnuaireExporte`) ; sinon `annuaireVide` de la
  configuration ; `org`, `org_id`, `console_origin` égaux à la configuration,
  sinon refus de démarrer ; `registration_ttl_ms` recopié sans opération
  (`annuaire_ttl_recopie`) ; amorce déclarée alors qu'un annuaire est
  persisté : `annuaire_amorce_ignoree` ; puis `recopierAdministrateurs`
  (EX-13.37), avant de servir aucune méthode du canal, et de nouveau à
  chaque rechargement de la configuration.
- Identifiants d'entrée tirés au hasard (`identifiant: "aleatoire"`).

### e.4 Notifications livrées par le service (13.19)

- Document `$defs/notification` de `configuration-approbation-v0` (`id`
  `ntf-` et 32 chiffres hexadécimaux tirés au hasard ; `kind` parmi
  `ouverture`, `escalade`, `nouveau_gel`, `seuil_inatteignable`,
  `vote_inscrit`, `operation_annuaire`, `plafond_atteint` ; destinataires et
  `details` de la table d'EX-13.40), formé après la persistance de ce qui le
  cause, sans aucune identité de personne ; `link` `<console_origin>/tickets/<ticket>`
  ou `<console_origin>/inscription` (EX-13.43). Le corps est le JCS du
  document ; la ligne de `notifications.ndjson` est ce corps, écrite avant la
  première tentative ; rotation au-delà de 64 Mio, 8 fichiers tournés au
  plus.
- Livraison (EX-13.41, EX-13.42) : `POST notifications.url`,
  `Content-Type: application/json`, `NOORTRACE-Signature:
  sha256=<HMAC-SHA256(K, "noortrace/notification/v0\n" ‖ corps)>`, sans
  redirection, certificat vérifié par `notifications.ca` ou le magasin du
  système, délai `notifications.timeout_ms` ; reprises à 10 s, 60 s, 300 s et
  1 800 s ; abandon sur tout statut hors 2xx, 408, 429 et 5xx ; file de
  10 000 au plus, éviction `file_pleine` qui épargne `vote_inscrit` et
  `operation_annuaire` ; jamais sur le chemin d'une réponse ni d'une
  transition. Journal du service : `notification_livree`,
  `notification_echec`, `notification_abandonnee`,
  `notification_sans_destinataire`, `notification_boite_en_echec`,
  `plafond_refus_non_notifies`.
- Remplacé : la notification `{ ts, kind, …, link }` de l'étape 4, le lien
  `<console_origin>/#ticket=<ticket>`, le `kind` `membres_ajoutes` (devenu
  `nouveau_gel`) et la remise à des écouteurs en mémoire
  (`supervision.ecouteurs`), qui ne livre rien.

### e.5 Configuration (EX-10.12)

- Document `configuration-approbation-v0` (copie embarquée sous `schemas/`,
  avec `annuaire-approbateurs-v0`, `evenement-v0`, `ticket-v0`), membres
  facultatifs à leur défaut ; règles `rpc_non_declare`, `rpc_tls`,
  `tls_exige`, `authentification_exigee`, `jeton_exige_production`,
  `jetons_egaux`, `escalade_non_croissante`, `webhook_http`, aux pointeurs de
  la table ; secrets (`storage_key` brute de 32 octets prise telle quelle,
  sinon 64 chiffres hexadécimaux ; jetons et `rpc.token` de 16 à 1 024
  caractères ; `notifications.key` de 32 à 1 024 ; TLS en PEM) ; écoute
  `etat` (TCP, sans TLS, `GET /v0/etat` seul, 404 `requete_invalide`
  sinon).
- `noortrace-approbation valider-configuration <fichier>` : rapport
  `$defs/rapport_validation`, erreurs `{ code, pointer }` triées par
  pointeur puis par code, `json`, `schema`, codes de retour 0, 1, 2 ; c'est
  la commande que TA-51 éprouve (`rpc` nul ou `developpement` refusé en
  production, `client` et `partenaire` acceptés).
- Au démarrage, un document refusé arrête le service avant toute écoute
  (code 1, mêmes erreurs sur la sortie d'erreur) ; `--config <fichier>`
  reste la seule option du service.
- La sonde `noortrace-approbation sonde --url <url>` des fichiers Compose
  n'est pas fixée par CT-3 (15.2, « ouvert ») : elle n'est pas écrite tant
  que le texte ne la fixe pas.

### e.6 Essais

Les quatre suites `test/approbation-service-*.test.js` restent vertes
(l'appel de `controleCanal` sur une instance d'`Annuaire` y devient l'appel
sur le document) ; nouvelles suites `test/approbation-service-*.test.js` :
méthodes du canal et ordre des refus (vecteurs `annuaire/` côté service,
traces rejouées sur le service réel), persistance et reprise après arrêt
brutal (annuaire et défis relus égaux), préséance d'EX-13.38, configuration
et `valider-configuration`, notifications reçues par un récepteur tiers
(TI-21, TA-102), `tickets` enrichi, TE-19, TI-14, TA-51, TA-77.
