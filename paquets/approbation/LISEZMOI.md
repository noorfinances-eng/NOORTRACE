# @noortrace/approbation — service d'approbation (CT-3)

Le service d'approbation de NOORTRACE, révision 0.6 de CT-3 : il valide et
évalue la politique d'approbation, tient les tickets et les fenêtres, lit et
fige le jeu d'approbateurs, vérifie les votes, applique la séparation des
tâches et la fenêtre de contestation, calcule les décisions et les remet au
noyau de l'enregistreur, qui les vérifie et les scelle. Il ne détient ni la
clé du journal ni aucune clé d'approbateur, n'écrit aucun événement et ne
signe rien (EX-3.3, EX-12.3).

Le service est un processus à part, joint par le noyau (`noortrace`) sur le
canal de CT-3 §12 ; le client côté démon est `ClientServiceApprobation` de
`@noortrace/enregistreur` (rubrique d de son `INTERFACES.md`). La console
d'exploitation (CT-3 §13, `@noortrace/console`) est cliente du canal de la
console (12.9), que le service sert en entier depuis l'étape 6 : les quatorze
méthodes d'EX-12.13, l'annuaire des approbateurs persisté dans l'état chiffré
(EX-13.38), et les notifications livrées à un webhook (13.19). Les règles de
l'annuaire ne sont pas écrites ici : elles sont celles du module d'annuaire
de la console (`@noortrace/console/annuaire`), importé. Ce que la console et
le démon utilisent est dans `INTERFACES.md`.

## Démarrer

```bash
noortrace-approbation --config /etc/noortrace/approbation.json
noortrace-approbation valider-configuration /etc/noortrace/approbation.json
noortrace-approbation valider-politique politique.json --environment production --expire-after-ms 3600000
noortrace-approbation sonde --url http://127.0.0.1:8601/v0/etat
noortrace-approbation --version
```

`valider-configuration` (EX-10.12) analyse le document en JSON strict, le
contrôle par `configuration-approbation-v0` puis par les règles de la table
d'EX-10.12, sans lire de secret, d'état ni d'écoute ; elle écrit une ligne
`{"valide":…,"errors":[{"code","pointer"}…]}` (erreurs triées par pointeur
puis par code), code 0 si le document est valide, 1 sinon, 2 sans fichier.
`sonde` (EX-12.22, révision 0.6) envoie `GET <url>` en HTTP, sans corps,
sans authentification ni redirection suivie, attend au plus 2 500 ms en
tout, écrit le corps reçu sur une ligne de la sortie standard, ou la raison
d'un échec sur la sortie d'erreur, et rend 0 sur une réponse 200 dont le
corps, en JSON strict, est `$defs/reponse_etat_service` de
`console-service-v0` (forme fermée d'EX-12.12), quelle que soit la valeur de
`ready` ; 1 dans tout autre cas, usage incorrect compris (`--url` absente,
vide ou répétée, argument inconnu) ; aucune autre valeur.

Au démarrage, le service consigne l'empreinte SHA-256 de ses fichiers
(`bin/`, `src/`, `schemas/`, `package.json`, CT-7 EX-3.10), relit son état
(EX-7.23), retient son annuaire dans l'ordre d'EX-13.38 et y recopie
`administrators` (EX-13.37), déclenche les minuteurs échus pendant l'arrêt,
relit le jeu des tickets ouverts, puis écoute ; il écrit alors sur la sortie
standard une ligne `{"pret":true,"pid":…,"noyau":{…},"console":{…},"etat":{…}}`.
Un refus au démarrage (EX-10.14, révision 0.6) l'arrête avant toute écoute,
code 1, avec une ligne `$defs/rapport_validation` sur la sortie d'erreur :
les erreurs de `valider-configuration` pour un document refusé, ou les codes
que seul le démarrage décèle, `reference_illisible` (secret illisible ou mal
formé, nommé par son pointeur, jamais par sa valeur), `jetons_egaux` (deux
valeurs égales) et `ecoute_impossible` (`/noyau`, `/console` ou `/etat` :
adresse prise, droits, adresse absente). Une cause qu'aucun code ne nomme
(état illisible, amorce de l'annuaire refusée) est écrite en texte, code 1. Il s'arrête
proprement sur SIGTERM ou SIGINT. Il refuse de s'exécuter sous root en
production.

## Fonctionnement

Une seule file traite les entrées une à une (`src/service.mjs`) : la machine
à états (`src/tickets.mjs`) déclenche d'abord les minuteurs échus (EX-7.7),
traite l'entrée, puis l'enregistrement est écrit et synchronisé ; la réponse
n'est rendue, et une remise livrée, qu'après (EX-7.22).

| Module | Domaine |
|---|---|
| `politique.mjs` | validation d'EX-4.2 et d'EX-8.2 (schéma, puis points 1 à 7, erreurs triées), avertissements d'EX-4.14 |
| `evaluation.mjs` | sélection, pointeurs, nombres exacts en `BigInt`, prédicats, logique de Kleene, issue, `policy.rule`, EVALUER, portée et fenêtres, CANDIDATS |
| `tickets.mjs` | machine à états de 7.5 (T1 à T22), minuteurs, rapprochement, votes, récusations, retraits, décompte, contestation, remises, fenêtres, effacement des arguments |
| `jeux.mjs` | jeu statique, comparaison, `source` d'EX-8.8, jeu exploitable |
| `lecteur-jeu.mjs` | lecture au registre (EX-8.1) et surveillance des journaux (EX-8.5) par JSON-RPC |
| `signatures.mjs` | objet A et D_A (fonctions du noyau), normalisation d'EX-9.3, recouvrement, SG-1 à SG-7 |
| `persistance.mjs` | journal d'état chiffré en ajout seul (EX-7.30), instantané, annuaire et défis, reprise, verrou |
| `annuaire.mjs` | état de l'annuaire (document courant, défis non expirés) et préséance au démarrage (EX-13.38) ; réexporte le module d'annuaire de la console, sans aucune règle propre |
| `vues.mjs` | vue de `consulter` (EX-12.14, EX-12.15), liste de `tickets` (EX-12.21), effets prévus, ticket vu par `controleCanal` |
| `notifications.mjs` | document `$defs/notification`, boîte d'envoi tournée, livraison signée au webhook, reprises, file, plafond (13.19) |
| `transport.mjs` | HTTP/1.1, JSON strict, deux canaux, jeton porteur, mTLS, prise Unix ; écoute d'état |
| `service.mjs` | méthodes de 12.2 à 12.6, canal de la console complet (12.9), `GET /v0/etat`, lecture du jeu, file unique, formation des notifications |
| `configuration.mjs` | `configuration-approbation-v0`, règles d'EX-10.12, secrets, défauts |
| `supervision.mjs` | journal du service, compteurs |
| `schema.mjs` | validateur JSON Schema 2020-12 des schémas embarqués (`schemas/`, copies de `spec/schemas`) |
| `demarrage.mjs`, `cli.mjs` | assemblage, ligne de commande |

## Fichiers sur disque

Sous `state_dir` (mode 0700) :

| Fichier | Contenu |
|---|---|
| `etat/journal.ndjson` | une ligne par entrée ou opération qui a un effet : `<n> <base64>`, enregistrement `{ meta, versions?, tickets?, fenetres?, annuaire?, defis? }` de documents entiers (`ticket-v0` `$defs/ticket` et `$defs/fenetre_ouverte`, `annuaire-approbateurs-v0`, tableau de `$defs/defi`) **sans les arguments en clair**, chiffré AES-256-GCM (EX-7.30 : nonce de 12 octets, données associées `noortrace/approbation/etat/v0` LF nature LF `n`) ; `fdatasync` avant toute réponse ; une entrée sans effet n'écrit rien ; un numéro n'est jamais réattribué |
| `etat/arguments/t-<ticket>`, `etat/arguments/f-<ticket>` | arguments en clair d'un ticket actif (`request.arguments`, `request.retained_event`, `request.arguments_piece`, `opening.scope.values`) ou valeurs de la portée d'une fenêtre ouverte, chiffrés (nature `arguments`) ; écrits (temporaire, `fsync`, renommage, `fsync` du répertoire) avant la ligne qui rend le ticket durable, supprimés après la ligne de son passage en `consomme`, `clos` ou `abandonne`, ou de la fermeture de la fenêtre (EX-7.24) |
| `etat/instantane.chiffre` | l'état complet (sans arguments) au dernier compactage (toutes les 2 000 lignes) ou à la reprise après un échec d'écriture, écrit par fichier temporaire, `fsync`, renommage, `fsync` du répertoire |
| `etat/verrou` | pid du service : un second service sur le même répertoire est refusé ; le verrou d'un processus arrêté brutalement est repris |
| `journal-service.ndjson` | journal du service, hors chaîne (3.4, 10.4) : démarrage et empreinte, chargements, avertissements de la politique, votes inscrits, lectures du jeu, remises, acquittements, refus du canal (`canal_console_refus`), opérations de l'annuaire (`operation_annuaire`, `operation_annuaire_refusee`), `annuaire_amorce_ignoree`, `annuaire_ttl_recopie`, livraison des notifications (`notification_livree`, `notification_echec`, `notification_abandonnee`, `notification_sans_destinataire`, `notification_boite_en_echec`, `plafond_refus_non_notifies`), alertes ; aucun argument en clair ni empreinte d'argument (EX-7.24), ni corps ni clé de notification (EX-13.42) |
| `notifications.ndjson`, `notifications.ndjson.1` à `.8` | boîte d'envoi (EX-13.39) : une ligne par notification, le corps JCS envoyé au webhook, écrite avant la première tentative, en clair (ni argument ni identité de personne) ; tournée au-delà de 64 Mio, 8 fichiers tournés au plus |

État relu à la reprise (EX-7.23) : versions chargées et version en vigueur,
jeux de repli, compteur d'identifiants, dernière date persistée, tickets
(recomposés de leur ligne et de leur fichier d'arguments), fenêtres, annuaire
et défis d'inscription non expirés (EX-13.38) ; rien d'autre. Les reprises
des notifications ne survivent pas à un redémarrage (EX-13.42). Un fichier d'arguments d'un ticket terminé ou inconnu est supprimé. La clé de rapprochement est recalculée des arguments
des tickets actifs. Une dernière ligne incomplète ou indéchiffrable est
tronquée (consigné `derniere_ligne_tronquee`) ; toute autre ligne illisible
arrête le démarrage.

## Configuration

Document `configuration-approbation-v0` (copie sous `schemas/`, CT-3
EX-10.12) ; l'exemple d'EX-10.12 est valide tel quel. Membres requis :
`version`, `environment`, `org`, `org_id`, `journal_id`, `state_dir`,
`storage_key`, `noyau`, `administrators` (1 à 64 identités canoniques
distinctes), `console_origin` ; les autres prennent le défaut de leur
description (`console`, `etat`, `rpc`, `notifications` nuls ;
`max_open_tickets` 20, `set_poll_interval_ms` 10 000, `registration_ttl_ms`
600 000, `remise_representation_ms` 30 000, `body_max_bytes` 16 777 216,
`socket_mode` 0660, `rpc.timeout_ms` 5 000, `notifications.timeout_ms`
10 000). Règles de la table d'EX-10.12, chacune à son pointeur :
`rpc_non_declare`, `rpc_tls`, `tls_exige`, `authentification_exigee`,
`jeton_exige_production`, `jetons_egaux` (références égales à la validation,
valeurs égales au démarrage), `escalade_non_croissante`, `webhook_http`,
`origine_port_par_defaut` (`console_origin` au port 443 écrit en clair,
révision 0.6) ; la boucle locale est `127.0.0.1`, `::1` (`[::1]` dans une
URL) ou `localhost`, écrits exactement ainsi, en minuscules, et comparés au
texte de l'hôte tel qu'il est écrit, avant toute normalisation : `127.1` ou
`LOCALHOST` n'en sont pas (révision 0.6).

Secrets, toujours par référence (`{ "file" }`, relatif au fichier de
configuration, ou `{ "env" }`), résolus au démarrage seulement :
`storage_key` (32 octets bruts pris tels quels, sinon 64 chiffres
hexadécimaux, `0x` facultatif, espaces de tête et de fin retirés) ; jetons des
canaux et `rpc.token` (16 à 1 024 caractères `[\x21-\x7e]`, espaces de tête
et de fin retirés) ; `notifications.key` (32 à 1 024 caractères, même
classe : sans espace intérieure, comme EX-10.12 révision 0.6 le dit des
quatre secrets textuels, quoique la clé ne passe dans aucun en-tête) ; `tls.cert`, `tls.key`, `tls.client_ca` et `notifications.ca` en PEM
(le premier certificat de `cert` est celui du serveur ; `cert` et `key`
peuvent désigner le même fichier).

- `noyau`, `console` : exactement une écoute (`socket` ou `tcp`). Le jeton du
  noyau est la valeur que référence `policy.approval.service.token` de
  l'enregistreur. `console.annuaire` : amorce de l'annuaire, lue seulement
  tant qu'aucun annuaire n'est persisté (EX-13.38).
- `etat` : écoute TCP sans TLS ni authentification qui ne sert que
  `GET /v0/etat` (404 `requete_invalide` sinon).
- `tickets.epoch` : `null` pour des identifiants de 65 bits aléatoires
  (`apr-` et 13 caractères), sinon une époque conservée hors du service et
  changée à chaque reconstruction (`apr-<époque>-0001`, EX-7.1). Les
  identifiants d'entrée de l'annuaire sont toujours tirés au hasard (64 bits).
- `rpc.validator` : `client` ou `partenaire` (exigé en production, CT-7
  EX-3.10), `developpement` ailleurs ; `rpc.token` est envoyé en
  `Authorization: Bearer`. Sans `rpc`, une politique `registre` laisse le
  service `non_pret` (alerte `jeu_registre_sans_rpc`).
- `notifications` : webhook de l'exploitant (`url`, `key`, `ca`,
  `timeout_ms`) ; nul, la boîte d'envoi est la seule trace.

## Lectures

Passages ambigus ou que le texte ne tranche pas, avec la lecture retenue.

1. **Identité du pair sur une prise Unix** (EX-12.2 : « le service authentifie
   le noyau de la même manière (identité du pair …) »). Node.js n'expose pas
   `SO_PEERCRED`, et le client du démon (`ClientServiceApprobation`) parle
   HTTP simple sur la prise, sans défi. Lecture : sur une prise, le service
   authentifie le noyau par les droits de la prise (créée en `0660` par
   défaut, jamais lisible par les autres, dans un répertoire qui n'est pas
   inscriptible par tous, sinon démarrage refusé) et, en production, par le
   jeton porteur, exigé.
2. **Refus d'authentification** : la table 12.8 n'a pas de raison propre.
   Lecture : HTTP 401, code `requete_invalide`, message `authentification`,
   consigné (`auth_refusee`).
3. **`non_pret` en mode observation** (EX-8.3 contre EX-11.12). EX-8.3 assure
   qu'une réponse `nouveau` porte un jeu ; en observation il n'y a jamais de
   ticket, et EX-11.12 (révision 0.4, plus particulière) fixe la réponse.
   Lecture : en observation, `evaluer` ne rend pas `non_pret`.
4. **Deuxième avertissement d'EX-4.14** (pointeur qu'une règle `champ` de
   rédaction réécrit) : `charger` transmet `/policy/approval` sans la
   politique de rédaction ; il n'est pas calculé par le service.
5. **Escalade d'un ticket « non décidé »** (EX-7.13). Lecture : les états de
   collecte (`ouvert`, `seuil_atteint`, `verification`) ; en `a_remettre`, la
   décision est calculée, une escalade n'a plus d'objet.
6. **Notification d'ouverture** (EX-7.12, révision 0.5 : « au premier gel de
   ce jeu »). La notification part au premier gel (aussitôt pour un jeu
   statique), formée après la persistance de l'entrée qui fige.
7. **Lecture qui re-fige un ticket en `verification`** (T5 et T8 sont deux
   lignes). Lecture : la lecture qui change le jeu fait le nouveau gel (T5) et
   ne vaut pas confirmation ; la lecture égale suivante confirme (T8).
8. **Re-présentation d'une remise livrée sans acquittement** : CT-3 fixe T12
   (`timeout_ms` après `temporaire`) et la re-présentation à la reprise
   (EX-7.23), pas le délai d'une remise perdue en route. Lecture :
   `remise_representation_ms` (30 s par défaut) après la livraison ; aussitôt
   après un redémarrage.
9. **Ré-émissions sans changement d'état** : la table 7.5 n'a de ligne que
   pour T21. Lecture : seules les ré-émissions qui changent le ticket (T21)
   entrent dans `transitions` ; les autres ne sont pas persistées (un agent
   qui réessaie ne grossit pas la trace).
10. **Contrôle d'`ouvrir`** (12.4 ne l'exige pas). Le service garde
    l'événement `retenue` et la pièce pour la console (EX-9.6) ; il refuse
    (`requete_invalide`) un événement non conforme au schéma, dont le hachage
    recalculé, le `seq`, le `ts`, `policy.ticket` ou `execution.status` ne
    sont pas ceux de la requête, ou une pièce qui ne vérifie pas la référence
    `execution.arguments`.
11. **Membres ajoutés par un nouveau gel** (EX-8.6 : « signalés à la console
    et dans la trace ») : `ticket-v0` n'a pas de membre pour eux. Lecture :
    ils sont dans les données de chaque transition `jeu_lu` (`added_members`,
    par rapport au jeu figé précédent) ; la vue (`added_members`) et la
    notification `nouveau_gel` (« adresses ajoutées depuis l'ouverture »)
    donnent les membres du jeu figé courant absents du premier jeu figé du
    ticket.
12. **Lecture `lu` d'un autre jeu que le jeu épinglé** (trace
    `jeu-reassigne`) : traitée comme `illisible` `jeu_non_attendu`
    (`set_reassigned`), sans gel ni changement du jeu de repli.
13. **Jeu de repli** : tenu par jeu épinglé ; un service est prêt (`ready`,
    EX-12.12) quand la version en vigueur a un jeu statique ou une lecture
    réussie de son jeu épinglé.
14. **Horloge qui recule** : une entrée n'est jamais datée avant la
    précédente (instant ramené à la dernière date traitée, persistée) ; un
    ticket échu ne rouvre pas.
15. **`charger` d'une version déjà chargée avec une autre empreinte** :
    refusée (`requete_invalide`) ; la même empreinte recharge la liste des
    outils et recalcule les candidats.
16. **Chiffrement au repos** (EX-7.24) : tout enregistrement d'état est
    chiffré, pas seulement les arguments ; la trace sans arguments reste lisible
    par l'export de la machine (`exporter`).
17. **Expiration sans jeu déclarable** (jamais figé, aucun repli) : aucune
    remise ; alerte `expire_sans_jeu` ; le noyau expire seul avec le jeu de la
    réponse `nouveau` (EX-12.11). Ne survient pas avec EX-8.3.
18. **Ordre des raisons de `recuser`** (non écrit) : `ticket_inconnu`,
    `ticket_non_ouvert`, `ticket_clos_aux_votes`, `jeu_non_fige`, `hors_jeu`,
    `auto_approbation`, `recuse`, comme pour un vote ; les traces de
    `tickets/` le confirment.
19. **Adresses connues de la lecture du jeu** (EX-8.1, pas 5) : adresses de
    l'annuaire courant (`adressesConnues`, tous états), de
    `separation.identities` des versions chargées, des jeux figés et du jeu de
    repli.
20. **Statuts HTTP des erreurs** (12.8 : « 4xx ou 5xx » ; rubrique e.2 des
    interfaces) : 400 (`requete_invalide`, `identite_invalide`,
    `message_invalide`), 403 (`session_non_autorisee`, `non_administrateur`,
    `auto_validation`, `revocation_non_autorisee`), 404 (`ticket_inconnu`,
    `entree_inconnue`, `adresse_inconnue`, `nonce_inconnu`,
    `demandeur_inconnu`), 409 (toute autre raison qui refuse une entrée de
    ticket ou une opération de l'annuaire, et `politique_inconnue`), 422
    (`politique_invalide`), 429 (`plafond_atteint`), 503 (`non_pret`) ; 401
    pour un canal non authentifié (lecture 2).
21. **Intention dans `evaluer`** : `$defs/requete_evaluer` n'admet qu'une
    chaîne ou `null` ; une intention portée par une référence (CT-2 EX-5.21)
    est refusée (`requete_invalide`). Voir le rapport du lot pour l'interface
    côté démon.
22. **Échec d'écriture de l'état** (EX-7.22 : « persister, avec `fsync` …
    chaque transition … **avant** d'en rendre l'effet visible » ; ni 7.10 ni
    12.7 ne disent quoi faire d'un `fsync` en échec). Lecture : l'entrée en
    échec ne reçoit pas de réponse (erreur 500, que le noyau tient pour une
    indisponibilité) ; le numéro attribué n'est jamais réattribué ; le
    magasin refuse tout ajout jusqu'à ce que l'état complet en mémoire soit
    recopié (instantané, fichiers d'arguments, journal vidé par un nouveau
    descripteur), ce que fait la première entrée suivante ou le premier
    `decisions` (qui ne livre rien tant que la recopie échoue). Un effet non
    rendu visible peut ainsi devenir durable (ticket créé, unité de fenêtre
    consommée) : le noyau, qui n'a pas eu de réponse, réessaie et reçoit la
    réponse idempotente (EX-7.20) ; jamais l'inverse (un effet visible perdu,
    relecture C, R-C-2).
23. **Effacement des arguments** (EX-7.24 : « effacés au passage en
    `consomme`, `clos` ou `abandonne` »). Lecture : l'effacement vaut pour
    toute copie sur disque, pas seulement le document courant ; les arguments
    sont donc tenus hors du journal en ajout seul, dans un fichier par ticket
    supprimé au passage même (voir « Fichiers sur disque ») : aucune ligne
    antérieure n'en garde copie (relecture C, R-C-7). Le document `ticket-v0`
    est recomposé à la reprise de sa ligne et de son fichier.
24. **Entrée sans effet** (EX-7.20 ; EX-7.23 : le service « relit ses
    documents … et rien d'autre »). Lecture : une entrée qui ne change ni
    ticket, ni fenêtre, ni version, ni état général (un `consommer` répété,
    un tic sans minuteur échu, un `evaluer` `autorise` hors fenêtre) n'est pas
    persistée ; l'instant de la dernière entrée est persisté avec tout
    enregistrement, et une entrée sans effet ne laisse rien que la reprise
    devrait relire (relecture C, R-C-10).
25. **Lecture et confirmation datées** (EX-8.7 : « une lecture faite
    **après** l'instant où la décision a été calculée » ; T8 : « d'instant ≥
    l'entrée en `verification` »). Lecture : l'instant d'une lecture est celui
    où elle commence (avant `eth_chainId`), pas celui où son résultat est
    traité ; une lecture partie avant le calcul de la décision met à jour la
    dernière confirmation mais ne déclenche pas T8, et une nouvelle lecture
    suit (relecture C, R-C-1). Une hauteur de confirmation inférieure à la
    hauteur de gel n'est pas refusée : EX-8.2 (« Le service croit le nœud
    qu'il interroge ») et T8 n'en font pas une garde, et une lecture partie
    après la décision part après la lecture de gel, la file des lectures étant
    unique.
26. **Lecture par jeu épinglé** (EX-7.7 : une entrée `jeu_lu` « vaut pour
    chaque ticket en `ouvert`, `seuil_atteint` ou `verification` » ; EX-7.21 :
    un changement de politique ne change pas « le jeu figés du ticket » ;
    EX-8.1 : la lecture compare `S` au jeu épinglé `approver_set.set`).
    Lecture : avec un seul jeu épinglé (traces de l'annexe A.6), une lecture
    vaut pour chaque ticket ; quand les versions chargées épinglent des jeux
    différents, le service lit chaque jeu épinglé (chaîne, registre, jeu) des
    tickets en collecte et de la version en vigueur, et une lecture ne vaut
    que pour les tickets dont la version épingle ce jeu, et pour le jeu de
    repli si la version en vigueur l'épingle. La donnée de l'entrée reste
    `{ status, jeu, cause }` ; le jeu visé passe à la machine hors de
    l'entrée (relecture C, R-C-9).
27. **Jetons distincts** (EX-12.4, EX-10.12 `jetons_egaux`) : par leur
    référence à la validation (même fichier, chemin résolu contre le
    répertoire de la configuration, ou même variable), par leur valeur au
    démarrage (relecture C, R-C-8).
28. **Vue d'un ticket dont les arguments sont effacés** (EX-12.14 ne nomme
    que `ticket_non_ouvert` après les points 1 à 3 ; `vue_ticket` exige
    `retained_event`). Lecture : un ticket `consomme`, `clos` ou
    `abandonne`, ou expiré sans événement `retenue`, n'a plus de vue :
    `consulter` rend `ticket_clos_aux_votes` (409) ; `tickets` le liste
    encore dans `related` s'il est refusé ou expiré.
29. **Intention de la vue** : `ticket-v0` n'a pas l'intention de la requête
    `evaluer`. Tranché par CT-3 révision 0.6 (EX-7.24, EX-12.14) : le service
    garde l'intention de la requête `evaluer` hors du document `ticket-v0`
    (`Machine.intentions`), la persiste dans le même fichier chiffré que les
    arguments en clair (`arguments/t-<ticket>`, membre `intent` du clair),
    l'efface avec eux et la rend telle quelle dans `request.intent`, y
    compris après une reprise ; elle n'est jamais tirée de
    `retained_event` (la lecture de l'étape 6, qui l'en tirait, rendait
    `null` pour une intention portée par une référence). Un état écrit
    avant ce changement n'a pas l'intention : la vue rend alors `null`.
30. **Effets de la vue** (EX-12.14 : « le gabarit d'effets de l'outil (CT-2
    EX-7.6) évalué sur les arguments »). Lecture : sur les valeurs rédigées
    de la pièce « arguments » (pas 1 d'EX-7.6), comme l'événement scellé les
    portera ; sans gabarit, l'effet par défaut d'une écriture (EX-7.6, (2)),
    aucun pour une lecture ; un membre tiré du résultat est `null` et listé
    dans `unresolved`, et n'entre pas dans la règle du couple
    montant/devise.
31. **Éligibles avant le gel** (EX-12.14 : « avant le gel, un membre du jeu
    de repli ») : membres du jeu de repli de la version du ticket (jeu
    statique de la politique pour une source `statique`), hors adresses du
    demandeur sous `interdite`, comme `eligible` après le gel ; la vue rend
    cette même liste dans `eligible` (avant l'assemblage, elle rendait la
    liste vide du ticket ; révision 0.6).
37. **Livraison au webhook** (EX-13.39, EX-13.42) : la tentative rend son
    statut à la ligne de statut, mais le délai `timeout_ms` court jusqu'à la
    fin du corps de la réponse (lu au plus jusqu'à 65 536 octets) et la
    prise est toujours détruite ensuite : un webhook qui ne finit jamais son
    corps ne garde aucune prise du service ouverte. Sans `notifications.ca`,
    les autorités sont celles du magasin du système
    (`tls.getCACertificates("system")`), et non la liste intégrée de Node.
32. **Dernier instant du seuil** (`last_threshold_at`, EX-10.9) : échéance
    moins `contest_ms` moins 1 ms, la fin de fenêtre devant précéder
    l'échéance (EX-7.7) ; nul si `contest_ms` vaut 0 ou sans échéance.
33. **`tickets`** : tickets non décidés (`reserve` à `a_remettre`, EX-14.1),
    triés par identifiant ; `votes_approuve` et `votes_refuse` comptent les
    votes courants.
34. **Persistance de l'annuaire** (EX-13.38, point 1 ; EX-12.17) : tant que
    l'annuaire n'est pas persisté, un défi est persisté seul (membre
    `defis`) ; une inscription refusée après le pas 4 d'EX-13.15 persiste le
    défi marqué présenté. Un `registration_ttl_ms` recopié sur un annuaire
    persisté est persisté au démarrage, sans opération (point 5).
35. **Rechargement de la configuration** (EX-13.37 : « quand le service
    démarre ou recharge sa configuration ») : le service ne recharge pas sa
    configuration en cours de route ; la recopie se fait à chaque démarrage.
36. **Notifications et entrées refusées** : une notification n'est formée
    qu'après la persistance réussie de ce qui la cause ; après un échec
    d'écriture, les causes attendent l'enregistrement suivant qui réussit.

## Tests

`test/approbation-service-vecteurs.test.js` (familles de `spec/vecteurs/ct-3`
et inventaire), `test/approbation-service-exigences.test.js` (EX- et TK-,
couverture), `test/approbation-service-hostile.test.js`,
`test/approbation-service-parcours.test.js` (processus de bout en bout) ;
étape 6 : `test/approbation-service-configuration.test.js` (EX-10.12, écoute
d'état, sonde, TA-51), `test/approbation-service-console.test.js` (canal de
la console, traces `annuaire/traces/*`, `tickets`, TI-14, TA-77),
`test/approbation-service-persistance.test.js` (EX-7.30, EX-13.37,
EX-13.38, TE-19, intention relue après un arrêt brutal), `test/approbation-service-notifications.test.js` (13.19,
TI-21, TA-102 ; récepteur tiers en Python,
`test/fixtures/approbation-service/recepteur_webhook.py`).

Aucun fichier n'est repris de noorchain-core.
