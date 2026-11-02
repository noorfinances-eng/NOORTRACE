# @noortrace/approbation — service d'approbation (CT-3)

Le service d'approbation de NOORTRACE, version 0.4 de CT-3 : il valide et
évalue la politique d'approbation, tient les tickets et les fenêtres, lit et
fige le jeu d'approbateurs, vérifie les votes, applique la séparation des
tâches et la fenêtre de contestation, calcule les décisions et les remet au
noyau de l'enregistreur, qui les vérifie et les scelle. Il ne détient ni la
clé du journal ni aucune clé d'approbateur, n'écrit aucun événement et ne
signe rien (EX-3.3, EX-12.3).

Le service est un processus à part, joint par le noyau (`noortrace`) sur le
canal de CT-3 §12 ; le client côté démon est `ClientServiceApprobation` de
`@noortrace/enregistreur` (rubrique d de son `INTERFACES.md`). La console
(CT-3 §13) est l'étape 6 : ce paquet en sert seulement les entrées `voter`,
`recuser` et `retirer` (7.4), avec le contrôle de l'identité de session
d'EX-12.16 et d'EX-12.19 ; ce que la console utilisera est dans
`INTERFACES.md`.

## Démarrer

```bash
noortrace-approbation --config /etc/noortrace/approbation.json
noortrace-approbation valider-politique politique.json --environment production --expire-after-ms 3600000
noortrace-approbation --version
```

Au démarrage, le service consigne l'empreinte SHA-256 de ses fichiers
(`bin/`, `src/`, `schemas/`, `package.json`, CT-7 EX-3.10), relit son état
(EX-7.23), déclenche les minuteurs échus pendant l'arrêt, relit le jeu des
tickets ouverts, puis écoute ; il écrit alors sur la sortie standard une ligne
`{"pret":true,"pid":…,"noyau":{…},"console":{…}}`. Il s'arrête proprement sur
SIGTERM ou SIGINT. Il refuse de s'exécuter sous root en production.

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
| `persistance.mjs` | journal d'état chiffré en ajout seul, instantané, reprise, verrou |
| `annuaire.mjs` | annuaire en lecture, identité canonique d'EX-13.7, `controleCanal` |
| `transport.mjs` | HTTP/1.1, JSON strict, deux canaux, jeton porteur, mTLS, prise Unix |
| `service.mjs` | méthodes de 12.2 à 12.6, canal de la console, `GET /v0/etat`, lecture du jeu, file unique |
| `configuration.mjs` | document de configuration, secrets |
| `supervision.mjs` | journal du service, boîte d'envoi des notifications, compteurs |
| `schema.mjs` | validateur JSON Schema 2020-12 des schémas embarqués (`schemas/`, copies de `spec/schemas`) |
| `demarrage.mjs`, `cli.mjs` | assemblage, ligne de commande |

## Fichiers sur disque

Sous `state_dir` (mode 0700) :

| Fichier | Contenu |
|---|---|
| `etat/journal.ndjson` | une ligne par entrée traitée : `<n> <base64>`, enregistrement `{ meta?, versions?, tickets?, fenetres? }` de documents entiers (`ticket-v0` `$defs/ticket` et `$defs/fenetre_ouverte`), chiffré AES-256-GCM (nonce de 12 octets, données associées `noortrace/approbation/etat/v0`, nature, `n`) ; `fdatasync` avant toute réponse |
| `etat/instantane.chiffre` | l'état complet au dernier compactage (toutes les 2 000 lignes), écrit par fichier temporaire, `fsync`, renommage, `fsync` du répertoire |
| `etat/verrou` | pid du service : un second service sur le même répertoire est refusé ; le verrou d'un processus arrêté brutalement est repris |
| `journal-service.ndjson` | journal du service, hors chaîne (3.4, 10.4) : démarrage et empreinte, chargements, avertissements de la politique, votes inscrits, lectures du jeu, remises, acquittements, alertes ; aucun argument en clair ni empreinte d'argument (EX-7.24) |
| `notifications.ndjson` | boîte d'envoi des notifications (EX-7.12, EX-7.13, EX-13.3), que les canaux de la console (étape 6) délivreront : ticket, outil, échéance, lien, jamais les arguments |

État relu à la reprise (EX-7.23) : versions chargées et version en vigueur,
jeux de repli, compteur d'identifiants, dernière date traitée, tickets,
fenêtres ; rien d'autre. La clé de rapprochement est recalculée des arguments
des tickets actifs. Une dernière ligne incomplète ou indéchiffrable est
tronquée (consigné `derniere_ligne_tronquee`) ; toute autre ligne illisible
arrête le démarrage.

## Configuration

```json
{
  "version": 0,
  "environment": "production",
  "org_id": "0x…", "journal_id": "0x…",
  "state_dir": "/var/lib/noortrace-approbation",
  "storage_key": { "file": "/etc/noortrace/approbation/cle-stockage" },
  "noyau": { "socket": "/run/noortrace/approbation.sock", "socket_mode": "0660", "token": { "file": "jeton-noyau" } },
  "console": { "tcp": { "host": "127.0.0.1", "port": 8711 }, "token": { "env": "NOORTRACE_JETON_CONSOLE" }, "annuaire": "annuaire.json" },
  "tickets": { "epoch": null },
  "max_open_tickets": 20,
  "escalation": [ { "after_ms": 900000, "notify": "jeu" } ],
  "set_poll_interval_ms": 10000,
  "administrators": [ "oidc https://idp.exemple admin-1" ],
  "console_origin": "https://console.exemple",
  "rpc": { "url": "http://127.0.0.1:8645", "validator": "client", "timeout_ms": 5000, "logs_from_block": 0 },
  "remise_representation_ms": 30000,
  "body_max_bytes": 16777216
}
```

- `storage_key` : 32 octets bruts ou 64 chiffres hexadécimaux, fichier
  (chemin relatif au fichier de configuration) ou variable d'environnement.
- `noyau`, `console` : exactement une écoute (`socket` ou `tcp`) ; TLS (`tls`
  : `cert`, `key`, `client_ca` pour le mTLS) exigé hors de la boucle locale ;
  jeton ou mTLS exigé en TCP ; jeton exigé en production ; les deux jetons
  distincts (EX-12.4). Le jeton du noyau est la valeur que référence
  `policy.approval.service.token` de l'enregistreur.
- `tickets.epoch` : `null` pour des identifiants de 65 bits aléatoires
  (`apr-` et 13 caractères), sinon une époque conservée hors du service et
  changée à chaque reconstruction (`apr-<époque>-0001`, EX-7.1).
- `rpc.validator` : `client` ou `partenaire` (exigé en production, CT-7
  EX-3.10), `developpement` ailleurs. Sans `rpc`, une politique `registre`
  laisse le service `non_pret` (alerte `jeu_registre_sans_rpc`).
- `console.annuaire` : document `annuaire-approbateurs-v0` lu au démarrage ;
  ses `administrators` sont remplacés par ceux de la configuration, qui font
  foi (13.4).

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
6. **Notification d'ouverture** (EX-7.12 : « à l'ouverture (T2) … les membres
   éligibles du jeu figé »). Avec un jeu `registre`, le jeu n'est figé qu'à la
   première lecture qui suit T2. Lecture : la notification part au premier gel
   (aussitôt pour un jeu statique).
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
    ils sont dans les données de la transition `jeu_lu` (`added_members`) et
    notifiés.
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
    l'annuaire lu (tous états), de `separation.identities` des versions
    chargées, des jeux figés et du jeu de repli.
20. **Statuts HTTP des erreurs** (12.8 : « 4xx ou 5xx ») : 400
    (`requete_invalide`, `identite_invalide`), 403 (`session_non_autorisee`),
    404 (`ticket_inconnu`), 409 (refus d'une entrée, `politique_inconnue`), 422
    (`politique_invalide`), 429 (`plafond_atteint`), 503 (`non_pret`).
21. **Intention dans `evaluer`** : `$defs/requete_evaluer` n'admet qu'une
    chaîne ou `null` ; une intention portée par une référence (CT-2 EX-5.21)
    est refusée (`requete_invalide`). Voir le rapport du lot pour l'interface
    côté démon.

## Tests

`test/approbation-service-vecteurs.test.js` (familles de `spec/vecteurs/ct-3`
et inventaire), `test/approbation-service-exigences.test.js` (EX- et TK-,
couverture), `test/approbation-service-hostile.test.js`,
`test/approbation-service-parcours.test.js` (processus de bout en bout).
