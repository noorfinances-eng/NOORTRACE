# @noortrace/inscription — inscription des clients par l'exploitant (CT-4 §7)

L'application d'exploitant de CT-4 §7.14 : une interface web (Next.js
16.4.6, React 19.3.1), qui ne tient aucune clé, et un agent séparé et
privilégié, joint par une prise locale `AF_UNIX` dont il vérifie le compte du
pair, qui conduit les pas de l'inscription d'un client (CT-4 §7.1), tient le
dossier `inscription-client-v0` et produit le paquet client de CT-4 §7.13.

**État : étape 6 faite.** Le contrat est dans `INTERFACES.md` ; chaque
section y porte son état et les précisions apportées par la construction.

Fichiers repris de noorchain-core : aucun. Les patrons de la console de la
Fondation (`dapps/foundation` : comptes de l'exploitant, périmètre public,
boucle de travaux d'un agent séparé) sont repris sans code : rien n'est
recopié, aucun commentaire, aucune donnée.

Complément du 2026-11-17, décision du porteur (présentation des écrans) :
les écrans portent le thème commun des écrans NOORTRACE, dans la grammaire
des hubs NOORCHAIN (deux états, sombre et clair ; mêmes valeurs de palette),
sans Tailwind ni composant recopié : le bloc de jetons et de composants en
tête de `src/web/app/globals.css` est écrit pour NOORTRACE et commun, à
l'octet, à la console d'approbation et à la page de vérification. La
bascule de thème reprend du hub son patron (clé `noor.theme` du stockage du
navigateur, toute valeur autre que `clair` vaut `sombre`), récrit dans
`src/web/lib/theme.mjs`. Aucune police, aucune image, aucune dépendance
n'est ajoutée. Le détail est dans `INTERFACES.md` 2.4.

Complément du 2026-11-18, décision du porteur (langage des écrans) : les
textes de l'interface sont écrits pour la personne de l'équipe qui inscrit
un client et qui n'est pas développeuse : nom courant et explication de
chaque étape, prochaine action écrite comme une consigne, erreurs qui
disent quoi faire, valeurs exactes gardées dans le détail replié. Trois
aides de saisie remplissent un champ dans la page sans rien envoyer
(empreinte de la pièce d'une confirmation, date et heure, nom court tiré au
hasard). Le bouton qui envoie un document signé nomme le compte qui envoie
(notre compte d'envoi) ; l'envoi par une référence, pour les essais, est une
action rangée. Les routes, l'agent et la forme du dossier ne changent pas.
Le détail est dans `INTERFACES.md` 2.5.

## Arborescence

```text
bin/noortrace-inscription-agent   agent : --config <fichier> (INTERFACES.md 3.1)
bin/noortrace-inscription-web     interface : --config <fichier>, sert le résultat de « next build »
schemas/                          copies à l'identique de spec/schemas (INTERFACES.md 0.4)
src/index.mjs                     API programmatique (ci-dessous)
src/commun/                       modules partagés : champs typés, références de clés, formes des travaux,
                                  schémas, JSON strict, paquet client et controlerPaquet (EX-7.22)
src/agent/                        agent : configuration, prise et compte du pair, file, données, instance,
                                  OP-1 à OP-12, envoi et capture, commandes, contrôle 8, paquet
src/web/                          projet Next.js : app/ (pages, routes, globals.css), composants/ (barre haute,
                                  formulaires, icônes), lib/ (serveur, données, mots du parcours, thème),
                                  proxy.mjs, next.config.mjs
```

## Construire et lancer

```bash
npm ci                                              # dépendances de l'espace de travail (verrou)
npm run compile                                     # hh-artifacts/ : code de création de CuratorSet
npm run construire-interface -w @noortrace/inscription   # next build de src/web (sortie src/web/.next/, ignorée par git)
noortrace-inscription-agent --config /etc/noortrace-inscription/agent.json
noortrace-inscription-web --config /etc/noortrace-inscription/interface.json
```

La construction n'a besoin d'aucun réseau extérieur : la télémétrie de Next
est coupée par la commande, aucune police ni ressource distante n'est
employée, et le binaire `@next/swc-*` de la plateforme est une dépendance
facultative du verrou (licence MIT).

L'agent se lance depuis la racine du dépôt quand il sert le réseau de
développement sans manifeste (EX-7.2) : il y lit `deployments/noorcore.json`,
`chain/config/alloc-dev.json`, `chain/runtime/validators.json` et
`hh-artifacts/contracts/CuratorSet.sol/CuratorSet.json`.

### Configuration de l'agent (INTERFACES.md 3.1)

```json
{
  "version": 0,
  "prise": "/run/noortrace-inscription/agent.sock",
  "interface_uid": 991,
  "donnees": "/var/lib/noortrace-inscription",
  "nature": "developpement",
  "instance": null,
  "rpc": ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"],
  "jeton": null,
  "comptes": { "exploitant": "hardhat:0" },
  "cles": { "repertoire": "/etc/noortrace-inscription/cles", "alias": { "chaine-client-essai": "fichier:/etc/noortrace-inscription/cles/chaine.cle" } },
  "delai_s": 120
}
```

Règles de la revue de l'étape 8 (révisions de CT-4 EX-7.1, EX-7.3, EX-7.25,
EX-7.28 demandées) :

- `cles` (facultatif) : `repertoire` est le seul répertoire dont un travail
  peut désigner un fichier (`fichier:`, `graine:`, chemin direct sous lui,
  sans lien symbolique) ; `alias` nomme des références de la configuration
  qu'un travail désigne par `alias:<nom>` ; sans `cles`, un travail ne
  désigne aucun fichier et `env:` n'est jamais admise dans un travail.
- Une référence d'un travail qui ne se résout pas rend à l'interface un seul
  message (« référence non résolue … ») ; le détail (forme, motif, jamais une
  valeur) va au journal de l'agent (`reference_non_resolue`).
- En production, `fichier:` et `env:` sont refusées pour tout rôle, clé de
  chaîne du client comprise (classe de garde D ; CLE-2 exige A, B ou C) : en
  version 0, l'agent n'y résout aucune clé et n'y conduit que les travaux
  sans clé (capture, export, vérification, condensés, paquet).
- En production, un point `rpc` en `http://` hors de `127.0.0.1`, `::1` et
  `localhost` est refusé au démarrage, et OP-2 contrôle tous les points
  avant le premier appel : le jeton ne part jamais vers un point refusé.
- Le nonce d'un envoi est lu sur chaque point `rpc` et recoupé comme dans
  le composant d'ancrage (CT-4 EX-8.14, précision et complément du
  2026-11-17) : avec plusieurs points, la plus grande valeur rendue par au
  moins deux d'entre eux ; aucune valeur rendue par deux points, ou un point
  au-delà de cette valeur + 1, et rien n'est signé (`nonce_incoherent`,
  transitoire : relancer quand les points concordent). Un point en retard
  ne bloque pas. Le nonce n'est jamais inférieur au plancher des envois de
  l'expéditeur dont l'inclusion est écrite dans les captures du client ; le
  déploiement du jeu est signé au nonce qui a servi au calcul de son adresse.
- L'agent relit l'instance à chaque travail : une révision du manifeste qui
  change sa nature ou ses identifiants refuse le travail
  (`instance_illisible`).
- `fees.max_daily_budget_gas` nul dans le manifeste vaut « aucun plafond »
  (comme son schéma le dit) ; `budget_jour` d'un travail est borné à 2^53 − 1.

### Configuration de l'interface

`noortrace-inscription-web --config <fichier>` ; document JSON strict :

| Membre | Contenu |
|---|---|
| `version` | `0` |
| `ecoute` | `{ "hote", "port" }` : adresse d'écoute du serveur Node (derrière le mandataire TLS de l'exploitant) ; en production, `127.0.0.1`, `::1` ou `localhost` seulement |
| `origine` | origine de l'interface, `https://…` en production : l'en-tête `Origin` exigé hors GET, et l'en-tête `Host` doit en être l'autorité (421 sinon) |
| `prise` | chemin de la prise de l'agent (lu par le serveur seulement, jamais envoyé à la page) |
| `donnees` | répertoire des données de l'agent, lu en lecture seule par le groupe de l'interface |
| `comptes` | `fichier:<chemin>` du fichier des comptes (`configuration-console-v0#/$defs/fichier_comptes`), fichier du compte du serveur en `0400` ou `0600` |
| `nature` | `developpement` ou `production` (affichage et forme des champs ; l'agent tranche) ; en production, `Strict-Transport-Security` sur chaque réponse |

Prêt, le binaire écrit `{"pret":true,"pid":<n>,"url":<adresse>}` sur la
sortie standard ; les messages de Next vont sur la sortie d'erreur.

Comptes et sessions de l'interface (revue de l'étape 8, CT-7 CLE-37) :
le verrou progressif de la connexion vaut par couple
(adresse cliente, nom), de sorte qu'un tiers qui échoue depuis une autre
adresse ne ferme pas le compte de l'exploitant ; l'adresse cliente est celle
du pair, ou, en production (boucle locale derrière le mandataire TLS), la
dernière adresse de `X-Forwarded-For` posée par le mandataire, qui doit donc
la poser ; les sessions échues sont purgées à chaque ouverture et au plus
10 000 sessions sont tenues. Ces comptes locaux et la clé de MAC des cookies
n'ont pas encore de ligne à l'inventaire de CT-7 §4.2 (ligne CLE-37
demandée) ; un système d'identité OIDC, exigé en production pour la console
(CLE-35), n'est pas offert par cette interface en version 0 : c'est un
risque nommé, à lever quand le code OIDC du serveur de console pourra être
réemployé (il n'est pas exporté par `@noortrace/console`).

### Comptes du système (EX-7.28)

- L'agent tourne sous son propre compte ; l'interface sous un autre, dont
  `interface_uid` est l'identifiant. L'agent refuse de démarrer si
  `interface_uid` est son propre compte ou le compte 0, ou s'il tourne
  lui-même sous le compte 0 (EX-7.23 ; revue de l'étape 8, CT-4 EX-7.28) : sous un
  seul compte, l'interface lirait le jeton et les clés et écrirait les
  registres sans passer par la prise. Seule l'API programmatique admet
  `memeCompteAdmis` (essais).
- Limites de ce contrôle : les membres du groupe sont lus dans `/etc/group`
  et `/etc/passwd` seulement (un membre connu par un annuaire LDAP ou sssd
  n'est pas vu) ; les répertoires parents de la prise ne sont pas contrôlés ;
  l'auxiliaire `python3` est résolu par `PATH`.
- Le répertoire de la prise appartient au compte de l'agent, en `0750`, et
  son groupe n'a pour membre que le compte de l'interface (liste de
  `/etc/group` et comptes dont c'est le groupe principal, `/etc/passwd`) ;
  l'agent refuse de démarrer sinon. La prise est créée en `0660` et prend le
  groupe du répertoire (bit setgid du répertoire, ou `chown` quand l'agent le
  peut).
- Les données appartiennent au compte de l'agent, en `0750`, groupe de
  l'interface : poser le bit setgid (`chmod 2750`) pour que chaque fichier
  créé prenne ce groupe. Les fichiers sont créés en `0640`, les répertoires en
  `0750`.
- Python 3 est exigé à l'exécution de l'agent (étape 6) pour
  lire le compte du pair.

### Compte du pair : mesure refaite le 2026-11-11

Node 22.22.0 n'offre pas `SO_PEERCRED`. L'agent écoute
`net.createServer({ pauseOnConnect: true })` ; à chaque connexion, il passe
le descripteur, sans le lire, au quatrième flux d'un processus `python3 -I`
(`AUXILIAIRE_PAIR` de `src/agent/index.mjs` : `socket.socket(fileno=3)`,
`getsockopt(SOL_SOCKET, SO_PEERCRED, 12)`, `detach()`), lit `pid uid gid` sur
sa sortie, puis reprend la connexion. Mesure refaite avec le module de
l'agent (Node 22.22.0, Python 3.13.16) : compte du pair lu
(`{"pid":3034,"uid":0,"gid":0}`, égal à celui du client), `bytesRead` nul
avant et après le contrôle, données (`bonjour`) lues ensuite par l'agent.
L'essai `test/inscription-agent.test.js` le refait sous deux comptes quand il
tourne en superutilisateur : le superutilisateur, qui n'est pas le compte de
l'interface, est fermé avant toute lecture (`octets_lus` 0, refus
`pair_refuse` consigné), le compte de l'interface est admis.

## API programmatique (sans navigateur)

L'agent se pilote par sa prise, sous le compte de l'interface, ou par l'API
du paquet :

```js
import { remettreTravail, remettreConfirmation } from "@noortrace/inscription/client";

const r = await remettreTravail("/run/noortrace-inscription/agent.sock", "exploitant operateur-1", {
  commande: "inscrire-client-preparer",
  slug: "client-essai",
  parametres: { org: "client-essai", journaux: ["journal-principal"], approbateurs: ["0x…", "0x…", "0x…"], seuil: 2,
    admin_jeu: "0x…", cles_enregistreur: [/* documents cle_enregistreur */] },
});
// r = { accepte: true, id: "trv-…" } ; l'état se lit dans <donnees>/travaux/<id>.json, la sortie dans
// <donnees>/clients/<slug>/sorties/<id>.json (operations-registre-v0#/$defs/sortie).
```

`demarrerAgent(configuration, options)` (`@noortrace/inscription/agent`)
démarre l'agent dans le processus appelant, qui ne doit alors avoir aucune
prise d'écoute IP (EX-7.28 : l'agent le vérifie au démarrage) ;
`options.memeCompteAdmis` (essais seulement, jamais lu par le binaire) lève
le seul contrôle des comptes d'EX-7.23 ;
`controlerPaquet(repertoire)` (`@noortrace/inscription/paquet`) est le
contrôle de réception d'EX-7.22, utilisable par le client hors de
l'application.

Bornes des journaux et du contrôle du paquet (revue de l'étape 8) :
`journal-agent.ndjson` est tourné à 16 Mio (une génération gardée,
`journal-agent.ndjson.1`), les refus que le compte de l'interface peut
provoquer sans limite (`pair_refuse`, `requete_refusee`, `requete_erreur`,
`travail_refuse`, `confirmation_refusee`) sont consignés ligne à ligne
jusqu'à huit par minute et par événement, puis comptés dans une ligne
`refus_cumules` ; `confirmations.ndjson` n'est jamais tourné (une ligne par
action d'exploitant) ; `controlerPaquet` ne lit pas un fichier au-delà de
64 Mio (`fichier_trop_grand`) ni plus de 4 096 entrées (`trop_de_fichiers`).
Limite nommée : la liste des travaux de l'interface relit chaque
enregistrement de `travaux/` à chaque page, et le registre des confirmations
est relu en entier à chaque admission.

Observation de la revue (risque déjà nommé par CT-4 EX-5.3 et
EX-5.8, H7) : le code de création du `CuratorSet` d'un client vient de
`hh-artifacts/` sous le répertoire de travail de l'agent, sans empreinte
attendue ; qui écrit dans ce répertoire fait déployer un autre jeu au client,
et le réviseur recompile et compare.

## Écarts relevés et précisions

L'outil de référence n'est ni lu ni importé ; ses sorties ont été observées
en boîte noire et l'épreuve d'EX-7.24 les compare à celles de l'agent dans
les essais. Là où le texte ne fixe pas un détail, l'agent suit la forme que
l'outil rend sur le même état, et le point est consigné ici :

- `checks` : une vérification exécutée plusieurs fois (OP-11, CP-1 à CP-6,
  OP-12 de chaque transaction de `inscrire-client`) figure une fois, à sa
  première place ; une erreur peut nommer dans `error.check` une vérification
  qui n'est pas dans `checks` (étape `envoyee` sans reçu : OP-3 ; organisation
  inconnue de `condense` : OP-8 ; capture en échec : la vérification CP-
  fautive) ; la reprise d'une étape `incluse` ne refait que la capture (pas
  d'OP-12) ; OP-2 en `noeud_suiveur` laisse s'exécuter OP-1 avant l'arrêt.
- Membres des `outputs` non fixés par le texte : ceux que l'outil rend
  (`funded` d'`inscrire-client`, `approvisionner`, les deux formes de
  `capturer`, `verifier` avec `summary`, `warnings`, `n4`, `statement`).
- `inscrire-cle` sur une clé déjà inscrite sous le même journal et la même
  clé Ed25519 rend `deja_fait` avec les valeurs de l'étape du dossier, sans
  la modifier : une étape `echec` (inscription incluse par un autre) reste
  `echec` ; elle passe à `capturee` par le travail `capturer` de la
  transaction qui l'a accomplie (EX-7.29, révision 0.7), qui vérifie OP-11
  et OP-12 sur les valeurs de l'étape.
- `administrer-jeu` : ordre des vérifications et `outputs` observés sur
  l'outil (`--relayeur` : OP-5 du relayeur, OP-6, OP-5 du signataire et du
  nonce à la même place, OP-7, OP-3 ; `outputs` `{ operation,
  confirmation_sha256, transaction_hash, block_number, gas_used, cost_wei,
  capture }`).
- `confirmation_sha256` (revue de l'étape 8, CT-4 EX-8.21) : l'outil exige
  `--confirmation <fichier>` pour `approvisionner` et `administrer-jeu` et
  rend le SHA-256 du fichier ; l'agent, qui n'a que le `piece_sha256` saisi
  par l'exploitant dans la confirmation d'EX-7.26, rend celui de la
  confirmation qui autorise l'opération, sur `deja_fait` aussi.
- Provision du dossier (revue de l'étape 8) : `inscrire-client-preparer`
  et `inscrire-client` vérifient en OP-4, avant OP-5 comme l'outil, que
  `funding.funder` est la trésorerie du manifeste (`compte_inattendu`), que le
  budget ne dépasse pas `fees.max_daily_budget_gas` et que `amount_wei` est
  `P_k` recalculé depuis `fees` du manifeste (`provision_excessive`) ; la
  provision versée est toujours celle recalculée (`controlerProvisionDossier`
  de `base.mjs`, point commun).
- `paquet` : `secrets_checked` nomme les secrets cherchés et leur nombre,
  `{ count, references }`, chaque `{ option, reference }` (option de l'outil
  qui désigne le rôle, référence d'EX-7.3, jamais la valeur), triés par
  option puis par référence (références de clés qu'ont employées les travaux
  du client, jeton compris) ; il égale celui de l'outil quand l'exploitant
  lui donne les références employées pour cette inscription ; un compte de la
  configuration jamais employé pour ce client n'est pas cherché ; les
  noms des références cherchées sont dans le message d'un refus, jamais une
  valeur.
- Un champ hors de sa forme (slug, nom de journal, montant) est refusé avant
  l'exécution (`requete_invalide`, aucune sortie), où l'outil rendrait une
  sortie `jeu_invalide` ou `usage` : EX-7.25 exige le contrôle des champs
  typés.
- `instance-registre-v0` emploie `contains`, que `RegistreSchemas` refuse :
  le manifeste d'instance se valide par `verifierManifesteSchema` de
  `@noortrace/ancrage/registre`.
- Une lecture d'état refusée de façon transitoire (« state unavailable » :
  bloc annoncé avant que son état ne soit servi, observé sur le réseau de
  développement) est refaite, au plus 40 fois toutes les 250 ms.
- La politique de sécurité du contenu ajoute `connect-src 'self'` (inscrit au
  contrat, 2.3) : les formulaires de l'interface remettent les travaux par
  `fetch`, que `default-src 'none'` bloquerait.
- Corps des requêtes (relecture de l'étape 6, mesuré sur le serveur construit,
  `POST /api/connexion`) : avant la correction, un corps annoncé de 300 Kio
  dont 1 Kio seulement est envoyé, ou 300 Kio fragmentés sans fin, n'ont
  aucune réponse (Next attend la fin du corps avant le mandataire et la
  route), et 64 Mio fragmentés font croître la mémoire résidente de 56 Mio
  environ avant le 413 ; Next tronque d'ailleurs, sans le dire, un corps
  au-delà de sa borne de 10 Mio. Après : 413 en moins de 10 ms pour un
  `Content-Length` au-delà de 256 Kio, 411 pour un corps fragmenté, rien de
  lu ni de retenu, connexion fermée ; délai de 60 s par requête ; borne du
  mandataire de Next réglée à 256 Kio + 1 (contrat 2.3).

## Contrôle du paquet (EX-7.22)

`controlerPaquet` rend chaque écart `{ point, fichier, code, erreur }`, dans
l'ordre des six points ; `erreur` est le code d'EX-7.30 du point
(`paquet_manifeste`, `paquet_fichiers`, `paquet_forme`,
`paquet_organisation`, `paquet_jeu`, `paquet_captures`) ; motifs (`code`) :
point 1 `absent`, `illisible`, `schema`, `repertoire_illisible` (un écart au
point 1 arrête le contrôle) ; point 2 `fichier_non_ordinaire`,
`entree_double`, `fichier_absent`, `sha256_different`, `longueur_differente`,
`fichier_non_liste`, `fichier_obligatoire_absent`, `ordre_files` (la
première entrée hors de sa place) ; point 3 `forme` (dont une réponse brute
qui n'est pas une réponse JSON-RPC 2.0 complète), `ecriture` (document créé
qui n'est pas écrit selon EX-7.18), `dossier_non_fini` ; point 4
`org_different`, `org_id_different`, `instance_differente`,
`manifeste_instance_en_trop`, `manifeste_instance_absent`,
`manifeste_instance_different`, `dossier_absent`, `nom_repertoire` ; point 5
`jeu_different`, `gabarit_different` ; point 6 `index_absent`,
`index_illisible`, `fichier_capture_absent`, `sha256_capture_different`,
`capture_non_nommee` (fichier de `captures/` qu'aucun index ne nomme, ou
index qu'aucune étape ne nomme). `sortieControle` rend, du premier écart, la
sortie de `paquet-client controler` de l'outil de référence ; les essais la
comparent à celle de l'outil sur chaque copie altérée.

## Dépendances et licences

`next` 16.4.6, `react` et `react-dom` 19.3.1, à version exacte (installées
par `npm install --save-exact … -w @noortrace/inscription`), et les trois
paquets de l'espace de travail. Arbre de `next` 16.4.6 : MIT, Apache-2.0,
ISC, BSD-3-Clause, 0BSD, CC-BY-4.0 (`caniuse-lite`, données). Les binaires
facultatifs `@img/sharp-libvips-*` (LGPL-3.0-or-later) et `@img/sharp-wasm32`
(Apache-2.0 AND LGPL-3.0-or-later AND MIT) figurent au verrou comme
dépendances facultatives de `sharp` ; ils ne sont pas installés sur le poste
de construction de l'étape 6 (retirés de `node_modules/` après
l'installation) et n'entrent dans aucune image (étape 7) :
`images.unoptimized` fait que `sharp` n'est jamais chargé. `npm audit -w
@noortrace/inscription` : aucune vulnérabilité.

## Essais

| Fichier | Objet |
|---|---|
| `test/inscription-agent.test.js` | agent sur le réseau Hardhat 31337 : refus OP-, reprises d'EX-7.16, sorties comparées à l'outil de référence, prise et compte du pair (EX-7.28), références (EX-7.3, EX-7.25), confirmations (EX-7.26) |
| `test/inscription-agent-nonce-plancher.test.js` | nonce d'EX-8.14 sur le nœud factice : plancher des inclusions écrites, recoupement des points (`nonce_incoherent`) |
| `test/inscription-agent-nonce-deploiement.test.js` | déploiement du jeu sur le réseau Hardhat derrière trois points : signé au plancher, à l'adresse CREATE de ce même nonce |
| `test/inscription-application.test.js` | TE-22 : interface construite et lancée, agent réel derrière |
| `test/inscription-paquet.test.js` | TE-21 : paquet produit, recherche d'EX-7.21, `controlerPaquet`, exemples de CT-4 7.13 ; pas 10 |
| `test/inscription-reseau.test.js` | réseau de développement 2124 (en attente s'il n'est pas debout) : client fictif, épreuve d'EX-7.24 |
| `test/inscription-presentation.test.js` | présentation (INTERFACES.md 2.4), sans navigateur : bloc de jetons commun et règles propres de la feuille, libellé de chaque étape, de chaque état, de chaque commande et de chaque erreur des schémas, prochaine action, détail technique aux valeurs exactes, bascule de thème ; mutants du module du parcours tués ; complément du 2026-11-18 (INTERFACES.md 2.5) : libellés du langage courant, consigne de chaque prochaine action, envoi resté sans réponse avant toute autre consigne, erreurs (ce qui s'est passé, ce qui a été dépensé, quoi faire), travail « réussi » avec une étape en échec, aucun mot de technicien dans les textes du module |
| `test/inscription-presentation-chromium.test.js` | présentation dans Chromium par Playwright, interface construite et servie sur des données fictives (sans agent) : connexion et barre haute, bascule de thème et sa mémoire, liste, fiche et ses étapes à cinq états, blocs repliés et valeurs exactes, confirmations et paquet, formulaire et saisie refusée, 390 px et 1280 px ; complément du 2026-11-18 (INTERFACES.md 2.5) : aucun mot de technicien au premier niveau de chaque écran et de chaque état, aides de saisie de la confirmation et du nom court, aucun choix à faire ni présélectionné avant un envoi, erreurs en clair, états cohérents et premier écran de la fiche ; troisième lecture : fiches d'enregistreur collées une par zone (corps au caractère près), « Copier », phrase de chaque pas de la confirmation, confirmation attendue, heures dans l'ordre des étapes, adresses coupées en deux sur téléphone |
| `test/inscription-revue.test.js` | revue de l'étape 8 : comptes distincts (EX-7.28), production sans clé en clair (EX-7.3), points `http://` (EX-7.1), répertoire de clés et alias (EX-7.25), interface en production, verrou, sessions, hôte (CT-7 CLE-37), plafond nul et budget, instance relue, bornes ; un mutant sur copie du paquet par règle |

Outils : `test/fixtures/inscription/` (réseau Hardhat et pont noorcore,
agent et interface d'essai, outil de référence en boîte noire, données
fictives des essais de présentation).
