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
- **Annuaire** : `Annuaire` est en lecture ; les opérations (13.6), leur
  persistance (EX-12.17) et la recopie des administrateurs (EX-13.37) sont à
  ajouter ; `controleCanal` sert déjà les cinq méthodes contrôlées.

## d) Configuration et ligne de commande

Voir `LISEZMOI.md` (configuration, fichiers sur disque, lectures).
`noortrace-approbation --config <fichier>` écrit
`{"pret":true,"pid","noyau","console"}` sur la sortie standard quand il
écoute ; SIGTERM l'arrête proprement.
