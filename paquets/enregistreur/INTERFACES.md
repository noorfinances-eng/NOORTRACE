# Interfaces du cœur pour les lots suivants

Ce document s'adresse aux développeurs qui écrivent, en parallèle ou après ce
lot, les autres parties du démon `noortrace` : frontal MCP (CT-2 §4), frontal
modèle (§5), SDK et ingestion OpenTelemetry (§6), moteur de politique et
service d'approbation (§7.5, CT-3), rédaction (§10), WORM (§12.6, §12.11),
haute disponibilité (§13) et ancrage (CT-5). Avec CT-2 et les vecteurs de
`spec/vecteurs/ct-2`, il suffit : il n'est pas utile de lire le reste du
paquet, sauf `src/coeur.mjs` (la classe `Coeur`), `src/pieces.mjs` et
`src/capture.mjs`.

Le cœur ne parle à aucun hôte : il ne rend jamais lui-même de réponse
JSON-RPC ou HTTP. Il construit, scelle et rend durables les événements, et
lève des erreurs que le frontal traduit (table de 4.4, EX-14.5).

Règles communes :

1. **Ne changez ni les signatures ni les formes ci-dessous** sans adapter le
   cœur et ses tests dans le même changement ; le cœur ne connaît des frontaux
   que ces formes.
2. **Une pièce est écrite avant l'événement qui la cite** (EX-8.9, EX-12.6) :
   `await coeur.ecrirePiece(piece)` rend sa référence. L'écrivain refuse de
   sceller un événement dont une référence sans `value` n'est pas stockée
   (`ErreurConstruction`, EX-7.1).
3. **Rien n'est rendu à l'hôte avant que la promesse du cœur soit résolue**
   (EX-4.19, EX-12.6) : un événement rendu par le cœur est durable (fdatasync
   rendu sur le segment qui le contient, validation groupée d'EX-12.7).
4. **Erreurs.** `ErreurEnregistreur` porte `raison` (`stockage`, `cle`,
   `bail`, `horloge`, `attente`, `approbation`, `bail_non_detenu`,
   `politique`), `code` (`-31010` avant relais ; `-31017` quand un appel a
   déjà été relayé, EX-4.46) et `donnees` (jamais une donnée du client).
   `ErreurConstruction` est un bogue (EX-7.1) : l'appel entre en mode dégradé.
5. **Valeurs en clair** : elles ne quittent jamais la mémoire ; le cœur ne
   reçoit en clair que ce que CT-2 lui demande d'examiner (arguments pour
   `evaluer` et le MAC de relais, EX-7.4, EX-7.22). Les pièces et les valeurs
   des effets sont **rédigées** (EX-7.6).
6. **Pas d'horloge propre** : `ts`, `seq`, `prev_hash` sont fixés par
   l'écrivain (EX-7.8) ; les durées (`duration_ms`) viennent de l'horloge
   monotone du frontal (`coeur.horlogeBrute.monotone()`).

## Démarrage et objets communs

```js
import { Coeur, Piece, pieceJson, pieceTexte, pieceNonJson, pieceNonRedigeable,
         pieceDefinitionOutil, pieceListeAnnoncee, pieceErreurJsonRpc,
         pieceDeclarationSource, ErreurEnregistreur } from "@noortrace/enregistreur";

const coeur = await Coeur.demarrer({
  config,              // document validé (validerConfiguration, EX-15.4 pas 1 à 3)
  secrets,             // Map pointeur JSON → octets (resoudreSecrets, pas 4)
  octetsConfig,        // octets lus (sha256 consigné à `startup`)
  service,             // ServiceApprobation (client HTTP d'EX-7.14) ou null
  ancrage, worm,       // ComposantAncrage, SupportWorm (sections g et f)
  bail, signataire,    // MagasinBail, Signataire (sections f ; classes A à C)
  redaction,           // Redacteur, ou ses crochets (section e)
  reglesSupplementaires, // règles du pas 3 d'EX-15.4 des lots, rejouées au rechargement (section e)
  minuteurs, supervision,
  octetsLibres,        // (chemin) => Promise<number|null> : mesure de l'espace libre (essais ; défaut fs.statfs)
});
```

**Disque presque plein** (14.2) : `MagasinPieces(repertoire, { minOctetsLibres,
journal, octetsLibres })` porte le contrôle, `await pieces.verifierEspace(supplement?,
chemin?)`, qui lève `ErreurEnregistreur("stockage")` (`donnees.event = "disk_low"`)
sous `storage.min_free_bytes` et consigne `disk_low` (`free_bytes`,
`min_free_bytes`) à l'entrée sous le seuil, une fois jusqu'au retour
au-dessus. Il est appelé avant l'écriture de chaque pièce, par l'écrivain
avant l'ouverture de chaque segment, et par `coeur.tic()` toutes les
`CONTROLE_DISQUE_MS` (10 000) à l'horloge monotone du cœur. Au démarrage, un
disque sous le seuil laisse le démon démarrer en mode dégradé « stockage »,
sans segment ouvert ; les pas 2 à 4 d'EX-9.8 sont faits au tic qui ouvre le
nouveau segment. Un échec d'écriture d'une pièce par `coeur.ecrirePiece`
ferme le segment (`ecrivain.signalerPanneStockage`) : la sortie du mode suit
EX-14.11 au tic. `coeur.tic()` tient aussi `noortrace_pending_oldest_ms`
(§17).

Une **délégation** est l'objet `{ launched_by, on_behalf_of, scope, run_id }`
de CT-1 §5.3, résolu par le frontal selon 7.2 et EX-7.2 (valeurs déclarées
bornées avant d'entrer). Un **code** est `{ model, prompt_version }` ;
`policy_version` et `recorder` sont posés par le cœur (version en vigueur au
pas 3, ou `capture.policy_version` quand un appel en cours finit sous
l'ancienne version, EX-15.5).

Une **capture d'appel** (`appel`) est l'objet :

```js
{
  host: { id, launched_by, on_behalf_of, scope },   // entrée de mcp.hosts ou sdk.hosts
  delegation,                                       // 7.2
  tool_announced, tool_original, server_alias,      // 4.3 ; SDK : "<alias>__<tool>", EX-6.6
  class: "lecture" | "ecriture",                    // EX-14.1
  arguments,                                        // référence de la pièce « arguments » ÉCRITE
  context: [ref…],                                  // EX-7.7 (référence + kind)
  intent: string | référence | null,                // 5.6, EX-5.21 ; SDK : déclaré et rédigé
  code: { model, prompt_version },                  // corrélation 5.6
  policy_version?: string,
}
```

## a) Frontal MCP (§4)

### Signatures

```js
await coeur.ecrirePiece(piece) → référence
await coeur.evaluer(requeteEvaluer) → réponse validée (EX-7.16)
coeur.susceptible(nomAnnonce) → booléen (EX-7.4)
coeur.definirOutils([{ tool_announced, tool_original, server_alias, class, effects }])
await coeur.scellerRefus(appel, reponse) → événement `refusee`
await coeur.scellerRetenue(appel, reponse, argumentsEnClair) → { evenement | null, signal: "en_attente" }
await coeur.preparerRelais(appel, { reponse, argumentsEnClair, upstream_id, timeout_ms }) → relais
await coeur.terminerRelais(relais, { resultat, resultatRedige, argumentsRediges, duration_ms, is_error, sourceNonRedigeable }) → événement `executee`
```

### Contrat (4.4, pas 1 à 14)

- Pas 1 et 2 : lecture, refus, résolution, pièces de définition et de liste
  (`pieceDefinitionOutil`, `pieceListeAnnoncee`, EX-4.45) : frontal.
  `definirOutils` à chaque changement de la liste agrégée (EX-4.15) : le cœur
  renvoie `charger` (EX-7.15).
- Pas 3 : `coeur.evaluer({ tool_announced, tool_original, server_alias,
  arguments (en clair), class, delegation, intent, code, context })` ; une
  réponse hors d'EX-7.16, une erreur ou l'absence du service lèvent
  `ErreurEnregistreur("approbation")` (consigné) ; le frontal applique la
  matrice de 14.2 (bloquant pour une écriture et pour `susceptible(nom)`,
  passant pour une autre lecture si `policy.failure.approval_service.lecture`
  le dit, `decision: "autorise"`, `rule: null`).
- Pas 4 : rédaction (section e), puis `pieceJson(valeurRedigee, { redacted })`
  et `ecrirePiece` **avant** tout relais.
- Pas 5 : `refuse` → `scellerRefus` (sans ticket : `policy.decision:
  "refuse"` ; ticket `refuse`/`expire` : reprise de la `retenue`, EX-7.12),
  puis le résultat `isError: true` d'EX-4.49 (frontal).
- Pas 6 : `nouveau` → `scellerRetenue` (EX-7.17 ; lignes `retenue` et MAC
  durables avant l'ajout au segment, EX-12.23 ; `ouvrir` envoyé sans attendre,
  EX-7.18) ; `evenement: null` quand une `retenue` sans décision est déjà
  durable (renvoi d'`ouvrir`, signal `en_attente`). `en_attente` : aucun
  événement (frontal). Le mode `retenir` (EX-4.50) est du frontal : il garde
  la requête, et passe `{ held: true }` à `traiterRemise` (section d).
- Pas 7 et 8 : `preparerRelais` fait RL-1 à RL-4 pour un ticket `approuve`
  (EX-7.21 ; `ErreurEnregistreur("approbation")`, `donnees.verification`,
  alerte) et inscrit l'intention (deux lignes, fdatasync, EX-12.12) pour une
  écriture ou un appel soumis à approbation. **Le frontal ne relaie qu'après
  la résolution de cette promesse** (EX-4.19). `relais.intention.intent_id`
  est l'identifiant `i-<époque>-<n>` ; `upstream_id` est l'`id` amont
  (`e-` + douze chiffres).
- Pas 9 à 11 : relais, notifications, réponse : frontal (`t_envoi`,
  `t_reponse` monotones, EX-4.48).
- Pas 12 et 13 : `terminerRelais` avec la pièce « résultat » (non écrite :
  le cœur l'écrit avant l'événement), la valeur **rédigée** du résultat et des
  arguments (effets, EX-7.6), `duration_ms` et `is_error`. Le cœur lève
  l'intention (EX-12.13), envoie `consommer` pour le premier relais d'une
  approbation (EX-7.20). Une panne (stockage, clé, bail, horloge) lève
  `ErreurEnregistreur` de `code -31017` : l'événement est gardé en attente et
  scellé à la sortie du mode dégradé à la place d'un événement de reprise
  (EX-4.46, EX-14.10).
- Pas 14 : réponse à l'hôte après la résolution de `terminerRelais`.
- Lecture passante en mode dégradé « stockage » (EX-14.8) :
  `coeur.mettreEnAttente(partiel, pieces, { captured_at })` ; bornes
  d'EX-14.9 (`ErreurEnregistreur("attente")`). Avant le relais (pas 7),
  `coeur.attenteBornee()` rend la borne atteinte (`"pending_max_events"`,
  `"pending_max_bytes"`, `"pending_max_ms"`) ou `null` ; atteinte, le mode
  dégradé `attente` est entré et `pending_limit_reached` (`events`, `limit`)
  consigné. Le frontal MCP, le SDK et le frontal modèle l'interrogent.

### Sections de CT-2 à couvrir

§4 en entier (4.1 à 4.9, EX-4.1 à EX-4.50), §7.2 (délégation, `intent`),
EX-7.2, EX-7.3, EX-7.7, §14.1 à §14.3, EX-17.2 (lignes `tool_*`,
`call_blocked`, `approval_pending`), §19.5.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/pieces-mcp/appels/*` (le cœur en rejoue la part de §8 :
pièces de définition, de liste, d'arguments non rédigés, de résultat reçu ;
le reste — lignes rendues, signal d'EX-4.49, formes d'erreur `-31011`,
`-31013`, `-31014`, réécritures de `_meta` — est au frontal) ;
`pieces-mcp/agregation/*` (EX-4.11) ; `evenements/journal-demo/entrees.json`
(appels de seq 3, 5, 7 et corrélation) ; annexe A.

### Mise en œuvre (lot « frontal MCP », `src/mcp/`)

```js
import { FrontalMcp, ServeurConnecteurs, ServeurHttpMcp, demarrerFrontalMcp } from "@noortrace/enregistreur";

const mcp = await demarrerFrontalMcp(coeur, secrets, { redacteur, correlateur });  // cli.mjs, si mcp.enabled
// = new FrontalMcp({ coeur, secrets, redacteur, correlateur }) ; await frontal.demarrer()
//   + new ServeurConnecteurs({ frontal, socket: mcp.socket, tcp: mcp.connector_tcp, jetons })
//   + new ServeurHttpMcp({ frontal, jetons })                     // si mcp.http
await mcp.arreter();                                               // avant coeur.arreter()

const s = frontal.ouvrirSession({ hote, identite: { peer_user | jeton | oauth_subject }, transport: "stdio" | "http", emettre });
const texte = await frontal.recevoir(s, octets, { cadre: "ligne" | "corps", canal: { notifier, annulation } }); // réponse ou null
frontal.chargerListe(alias, tools, { ttlMs, cacheScope, ere });   // dernière liste reçue avec succès (EX-4.18)
```

`bin/noortrace-connecteur --socket <chemin>` (ou `--tcp <hôte:port>`, jeton
dans `NOORTRACE_CONNECTEUR_JETON` ; TLS par `NOORTRACE_CONNECTEUR_TLS_CA`,
mTLS par `NOORTRACE_CONNECTEUR_TLS_CERT` et `NOORTRACE_CONNECTEUR_TLS_KEY`,
chemins de fichiers PEM, LISEZMOI, lecture 135) est le connecteur stdio de
19.5.

Prise TCP authentifiée commune (`src/mcp/prise-tcp.mjs`), employée par la
prise des connecteurs (`mcp.connector_tcp`) et par celle du SDK
(`sdk.tcp_listen`, rubrique c) ; complément du lot « SDK et OpenTelemetry »
(lectures 113 et 134) :

```js
import { ecouterPriseTcp, identiteCertificat, chaineServeur, erreursPriseTcp, controleConnecteurTcp } from "@noortrace/enregistreur";

const serveur = await ecouterPriseTcp(tcp, {                       // tcp : $defs/tcp_listen
  nom, pointeur, connexions,                                       // messages ; prises à fermer à l'arrêt
  surJeton(c) {}, surMtls(c) {}, surEchecTls(raison) {} });         // TCP nu ou TLS (jeton), mTLS (certificat)
identiteCertificat(c)          // → { cn, empreinte } | { refus: "certificat:absent" | "certificat:<code>" | "certificat:sans_nom_commun" }
chaineServeur(pem)             // → { cert, autorites } : le certificat du démon, puis l'autorité des certificats clients
erreursPriseTcp(tcp, pointeur) // pas 3 d'EX-15.4 : client_auth mtls exige tls
controleConnecteurTcp(config)  // la même règle pour /mcp/connector_tcp, dans les règles de cli.mjs
```

`ServeurConnecteurs` sert `mcp.connector_tcp` en TCP nu ou TLS avec jeton,
et en mTLS : certificat vérifié contre l'autorité qui suit le certificat du
démon dans `tls.cert_file`, rattaché à l'entrée de `mcp.hosts` dont
`match.peer_user` est son nom commun (`identite = { peer_user,
certificat }`) ; refus consignés `auth_failed` (`transport: "stdio"`,
`tls: true`, `reason`). Essais : `test/enregistreur-mcp-tls.test.js`.

Ce que le frontal attend des autres lots, par des crochets facultatifs :

- **rédaction (e)** : le `Redacteur` passé au frontal ou, à défaut, celui
  donné au cœur (`Coeur.demarrer({ redaction })`) : `redigerArguments(valeur,
  { outil, alias, id, host })` et `redigerResultat(...)` (pièce, valeur
  rédigée, `non_redigeable`), `admettreRunId(v)` (EX-7.2). Une erreur JSON-RPC
  du serveur est remise à `redigerResultat` sous sa forme
  `{"noortrace_jsonrpc_error": …}`. Sans rédacteur, les pièces sont écrites
  telles quelles et `redaction_absente` est consigné une fois ;
- **frontal modèle (b)**, corrélation de 5.6 : `correlateur.correler({ host,
  host_group, run_id, tool_announced, arguments, t_recu })` →
  `{ intent, code: { model, prompt_version }, seq }` ou `null` ; une intention
  en référence est une pièce déjà écrite ;
- **moteur de politique (d)** : le mode observation (EX-4.51, 14.6) n'est pas
  appliqué par le frontal ; les autres réponses suivent EX-7.16 et la matrice
  de 14.2 (service indisponible : bloquant pour une écriture et pour
  `coeur.susceptible(nom)`, sinon `policy.failure.approval_service.lecture`).

Changements du cœur faits par ce lot (les plus petits qui complètent le
contrat, avec leurs tests dans `test/enregistreur-mcp-exigences.test.js`) :

```js
coeur.brancherRetention({ retient(ticket) → booléen, decidee(ticket, evenement) })  // mode retenir (EX-4.50)
coeur.brancherSante(() => ["serveur:<alias>", …])                                  // EX-4.18, EX-17.1
```

`held` (`acquitter.held`, EX-7.19 pas 3) est établi au scellement de la
décision, dans le même tour que la réclamation de la requête retenue :
`retient(ticket)` puis `decidee(ticket, evenement)`, appelé aussitôt et non
attendu ; vrai seulement pour une décision `approuve` retenue (relecture C) ;
le `consommer` du relais attend la fin de l'`acquitter`. Après une
expiration par le noyau seul, `decidee` est appelé sans être attendu ;
`etatSante()` ajoute les raisons du frontal sans faire entrer le cœur en mode
dégradé. `test/fixtures/enregistreur-coeur/outils.mjs` : `configurationDev`
désactive `mcp.enabled` sauf `{ mcp: true }` (les serveurs de l'exemple de
15.3 sont injoignables depuis les tests) et place `mcp.socket` sous le
répertoire du test.

## b) Frontal modèle (§5)

### Signatures

```js
await coeur.ecrirePiece(pieceRequete)        // avant l'envoi au fournisseur (EX-5.10)
await coeur.ecrirePiece(piecePromptSysteme)  // pieceTexte(texteRedige, { redacted })
await coeur.ecrirePiece(pieceReponse)        // pieceJson, ou pieceNonJson / pieceNonRedigeable (EX-8.7)
await coeur.scellerEchange({ delegation, code: { model, prompt_version }, intent,
  requete, reponse, duration_ms, is_error, context }) → événement `noortrace.modele.echange`
```

### Contrat

- `requete`, `reponse` : références des pièces écrites ; `intent` : chaîne ≤
  4096 ou référence d'une pièce `text/plain` (EX-5.21) ; `prompt_version` =
  `sha256` de la pièce « prompt système » (EX-8.6) ; `context` : `[]` sauf
  `echangeModele` du SDK (pièce de déclaration de source, EX-7.7).
- `policy.decision` est `sans_objet` ; `policy.redaction` est posé par le
  cœur d'après les références (`redacted`, EX-10.20).
- Un échange bloqué (14.2, colonne M) n'arrive jamais au cœur ; un échange
  relayé dont le scellement échoue va en attente (`mettreEnAttente`).

### Sections de CT-2 à couvrir

§5 en entier, EX-8.5 à EX-8.7, §13.5 (échanges en vol), EX-14.12.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/pieces-modele/*` (le cœur en rejoue la sérialisation et
la référence de chaque pièce publiée et `prompt_version` ; la dérivation des
pièces depuis la requête et la réponse est au frontal) ;
`evenements/journal-demo` (seq 2, 4, 8).

### Mise en œuvre (lot « frontal modèle », `src/modele/`)

```js
import { demarrerFrontalModele, MoteurEchanges, PasserelleModele, ServeurIcap, RecepteurMiroir,
  lancerAdaptateur, RegistreCorrelation, controleModele, uriPasserelle } from "@noortrace/enregistreur";

const modele = await demarrerFrontalModele(coeur, secrets, { redacteur, chargerJwks });  // cli.mjs, selon model.mode (EX-5.1)
// → { correlateur, passerelle, icap, miroir, arreter } ; desactive : tout à null
// = new RegistreCorrelation({ fenetreMs, monotone, ecrirePiece, origine, journal })
//   + new MoteurEchanges({ coeur, redacteur, registre })          // commun aux trois modes
//   + passerelle : new PasserelleModele({ coeur, secrets, moteur, chargerJwks }) ; await ecouter()  // model.listen, model.tls
//     icap       : new ServeurIcap({ coeur, moteur }) ; await ecouter() ; adresses()              // model.icap.listen, tls_listen
//     miroir     : new RecepteurMiroir({ coeur, moteur }) ; await ecouter()                     // model.mirror.socket
const mcp = await demarrerFrontalMcp(coeur, secrets, { correlateur: modele.correlateur });   // crochet de 5.6
await mcp.arreter(); await modele.arreter();                         // avant coeur.arreter() ; drain de 13.5
validerConfiguration(octets, { reglesSupplementaires: [controleModele] })  // EX-15.4 pas 3 : routes, modes, hôtes, OAuth, ICAP, TLS
uriPasserelle(config)                                                // audience d'un jeton oauth_subject (EX-5.8 point 2)
await lancerAdaptateur({ socket, ecoute: "127.0.0.1:0", sortie })   // bin/noortrace-miroir : copie → couples (EX-5.6)
```

Moteur d'échanges (`src/modele/echange.mjs`), employé par la passerelle,
le serveur ICAP et le récepteur du miroir :

```js
moteur.controlerQuota(hote, t, { echange })   // EX-4.47 : limit_* du quota atteint (call_blocked) ou null
await moteur.preparer({ route, trouve, hote, entetes, valeur, t_recu, mode, identite })
  // délégation, colonne M (sauf miroir), pièces « prompt système » et « requête » durables (EX-5.10)
  // → { etat } ou { refus: "hote_inconnu" | "degrade", raison }
const capture = moteur.capture(etat, { statut, entetes, notesReponse });  // capture.ecrire(octets) ; capture.terminer({ coupe })
await moteur.sceller(etat, { genre: "reponse" | "delai" | "hote_parti" | "inactivite" | "coupure", … })
  // pièces « réponse » et « intention », événement scellé, ou mis en attente (14.5, EX-14.12), ou perdu (exchange_lost)
```

Le frontal emploie le cœur sans le changer : `coeur.ecrirePiece` (pièces
« prompt système » et « requête » avant l'envoi, « réponse » et
« intention » après), `coeur.scellerEchange`, et, pour une panne après
l'envoi, `partielEchange` (`capture.mjs`) puis `coeur.mettreEnAttente(partiel,
pieces, { captured_at })` ; il lit `coeur.degrade`, `coeur.bailDetenu` et
`coeur.intervention` pour la colonne M de 14.2. Il rédige par
`redigerPiece` du rédacteur (section e) : `genre: "texte"` portée
`prompt_systeme` (pièce et chaînes porteuses en `inline`), `genre: "json"`
portée `requete` avec `origine` (requête reçue), portée `reponse`
(`avecValeur`), `genre: "octets"` pour un corps non JSON ou un flux brut ;
`admettreRunId`, `admettreNomPrompt`, `admettreValeurLigne` (segment de
modèle, EX-5.36).

Registre de corrélation, offert au frontal MCP (section a) et au SDK
(section c) :

```js
const e = registre.inscrire({ host, host_group, run_id, format, formeClair, interpose: true | false });  // false : echangeModele
registre.completer(e, { formeRedigee, code: { model, prompt_version } });   // quand la réponse rédigée est calculée
registre.sceller(e, seq);                                                   // après scellement
await registre.correler({ host, host_group, run_id, tool_announced, arguments, t_recu })
  // → { intent, code: { model, prompt_version }, seq | "inscription:<n>", declaree } ou null
```

`host` est l'entrée de connexion d'hôte de l'appel (`tool_name_template`,
`tool_name_sanitize`) ; `t_recu` et les instants d'inscription viennent de
`coeur.horlogeBrute.monotone()`. Pour le SDK (EX-5.22, 6.2), `tool_announced`
est le nom court déclaré ; seuls `code.model` et `code.prompt_version` du
résultat s'appliquent. Fonctions de dérivation réutilisables par le SDK
(EX-6.8) : `piecesRequete`, `pieceReponse`, `consoliderMorceauxGemini`,
`modeleDe`, `intentionDe`, `intentionBornee`, `appelsDemandes`.

Aucun changement du cœur n'a été nécessaire ; `src/cli.mjs` démarre le
frontal modèle après le cœur (un échec : `demarrage_refuse : frontal_modele`,
code 2, les fils de rédaction fermés pour que le processus sorte), remet son
registre au frontal MCP, l'arrête avant le cœur, et ajoute `controleModele`
aux règles du pas 3 d'EX-15.4. Le jeton OAuth de la passerelle est vérifié
par `verifierJwt` du frontal MCP avec `mcp.http.oauth` (LISEZMOI, lecture
72) ; les quotas emploient `QuotasHote` du frontal MCP (lecture 73).

## c) SDK et ingestion OpenTelemetry (§6)

### Signatures

```js
// debutAppel : pas 2 à 8
const reponse = await coeur.evaluer(...);                       // EX-6.7
await coeur.scellerRefus(appel, reponse);                       // refuse
await coeur.scellerRetenue(appel, reponse, argumentsEnClair);   // nouveau
const relais = await coeur.preparerRelais(appel, { reponse, argumentsEnClair,
  upstream_id: call, effetsDeclares });                         // autorise
// finAppel : pas 12 et 13
await coeur.terminerRelais(relais, { resultat, resultatRedige, argumentsRediges,
  duration_ms, is_error, effetsDeclares });
// ingestion OpenTelemetry : événement partiel construit selon EX-6.36
await coeur.scellerPartiel(partiel);
```

### Contrat

- `appel.tool_announced` vaut `<alias>__<tool>` (EX-6.6) ; `effetsDeclares`
  sont des effets de la forme de CT-1 §5.3, déjà soumis aux détecteurs de la
  portée `arguments` (EX-6.6) : ils remplacent le gabarit (EX-7.6) et entrent
  dans la ligne contexte d'intention (EX-12.12).
- `finAppel` ne rend `{ seq, hash }` qu'après la résolution de
  `terminerRelais` (EX-6.3).
- `fermer` d'une session avec un `debutAppel` d'écriture sans `finAppel` :
  rien à faire ; la relecture du journal d'intention produit l'événement de
  reprise au prochain démarrage (EX-12.15). Une reprise à chaud, sans
  redémarrage, est à ajouter au cœur par ce lot (même construction :
  `partielReprise` de `src/reprise.mjs`).
- OpenTelemetry : aucun appel à `evaluer`, aucune intention ; les pièces sont
  écrites puis `scellerPartiel` ; la réponse `200` après la résolution de tous
  les événements du lot (EX-6.38).

### Sections de CT-2 à couvrir

§6 en entier (EX-6.1 à EX-6.41), EX-7.7 (déclaration de source), EX-12.15.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/otel/*` (non rejoués par le cœur) ;
`pieces-modele/gemini-sdk-*`.

### Mise en œuvre (lot « SDK et OpenTelemetry », `src/sdk/`, `src/otel/`, `paquets/sdk-js/`)

```js
import { FrontalSdk, ServeurSdk, demarrerSdk, controleSdk, classeSdk,
         IngestionOtel, ServeurOtel, demarrerOtel, controleOtel, RegistreRecouvrement, TableDoublons,
         decoderJson, decoderProtobuf, normaliser, classer, projeterSpan, partielSpan } from "@noortrace/enregistreur";

const sdk = await demarrerSdk(coeur, secrets, { correlateur });     // cli.mjs, si sdk.enabled ; sdk.socket (0660), sdk.tcp_listen (jeton, TLS, mTLS)
// = new FrontalSdk({ coeur, redacteur, correlateur }) + new ServeurSdk({ frontal, socket, tcp, jetons })
const cx = frontal.ouvrirConnexion({ hote, identite });            // identité du pair (prise Unix), jeton (TCP) ou certificat client (mTLS)
const ligne = await frontal.recevoir(cx, octets);                  // une ligne JSON-RPC → la réponse, ou null
await frontal.fermerConnexion(cx);                                 // connexion perdue : sessions closes, reprise à chaud
const otel = await demarrerOtel(coeur, secrets);                   // cli.mjs, si otel.enabled ; otel.listen (TLS avec otel.tls)
// = new IngestionOtel({ config, journal, metriques, redacteur, jetons, monotone, ecrirePiece, sceller, panne, octetsLibres, version, recouvrement })
//   + new ServeurOtel({ ingestion, config, journal })
await otel.arreter(); await sdk.arreter();                         // avant coeur.arreter()
validerConfiguration(octets, { reglesSupplementaires: [controleSdk, controleOtel] })   // EX-15.4 pas 3, EX-6.24
```

SDK de langage JavaScript : paquet `noortrace-sdk` (`paquets/sdk-js/`, son
`INTERFACES.md`) ; il ne parle qu'à la prise du point d'entrée.

Prise TCP en mTLS (`client_auth: "mtls"`, LISEZMOI, lecture 113 ; serveur
commun avec la prise des connecteurs, `src/mcp/prise-tcp.mjs`, rubrique a) :
`tls.cert_file` porte le certificat du démon suivi de l'autorité des
certificats clients (`chaineServeur` les sépare) ; le certificat client est
exigé et vérifié à la poignée de main, puis rattaché à l'entrée de
`sdk.hosts` dont `match.peer_user` égale son nom commun (`identite = {
peer_user, transport: "mtls", certificat: <empreinte SHA-256> }`) ; refus
consignés `auth_failed` (`transport: "tls"`, `reason: "certificat:<code>"`
ou `"hote_inconnu"`).

Le point d'entrée SDK suit le frontal MCP pas pour pas, sans relayer : pas
1 (lecture stricte de la ligne, quotas d'EX-4.47 sauf pour `finAppel` et
`fermer`, validation d'EX-6.6), délégation de la session (7.2), corrélation
par le registre de 5.6 (`code.model`, `code.prompt_version` seulement ;
`intent` déclaré, rédigé par la portée `arguments`, borné par EX-5.21), pas 3
par `coeur.politique.evaluerAppel` (EX-6.7, matrice de 14.2, mode
observation), pas 4 (`redigerArguments`, EX-10.23), refus, retenue (jamais de
requête retenue), `preparerRelais` (RL-1 à RL-4, intention durable avant la
réponse de `debutAppel`), `terminerRelais` pour `finAppel`, `scellerEchange`
pour `echangeModele` (dérivation de `src/modele/extraction.mjs` et
consolidation de `src/modele/flux.mjs`, EX-6.8 ; échange déclaré inscrit au
registre de corrélation, `interpose: false`). L'ingestion OpenTelemetry n'appelle
ni `evaluer` ni `preparerRelais` : pièces écrites (`ecrirePiece`), puis
`scellerPartiel(partiel, { priorite: "basse" })`, span par span, réponse `200`
quand tous sont durables.

Changements du cœur faits par ce lot (les plus petits qui complètent le
contrat, avec leurs tests dans `test/enregistreur-sdk-exigences.test.js` et
`test/enregistreur-otel-exigences.test.js`) :

```js
await coeur.reprendreRelais(relais)              // reprise à chaud (EX-12.15, EX-6.13) : même construction que la reprise au démarrage
coeur._partielReprise(entree, piece)             // construction commune aux deux reprises (EX-12.14 pas 2, lecture 117)
coeur.mettreEnAttente(partiel, pieces, { captured_at, intent_id, host, genre })   // host, genre : en mémoire, pour le recouvrement (lecture 125)
coeur.ecouterScellements(({ genre, host, appel, evenement }) => …)   // registre de recouvrement (EX-6.34)
await coeur.scellerPartiel(partiel, { priorite: "basse" })           // EX-6.28 : après les événements des autres frontaux en file
await coeur.scellerEchange({ …, host })                              // `host` : id de la connexion d'hôte (recouvrement)
```

- `preparerRelais` garde dans sa poignée l'événement partiel inscrit dans la
  ligne contexte d'intention (`partielIntention`), que `reprendreRelais`
  reprend : événement de reprise `executee`, `is_error: true`, pièce
  `noortrace_reprise`, levée de l'intention, `intent_recovered`
  (`session_closed: true`), `consommer` pour un ticket approuvé (EX-6.7) ;
  à l'arrêt du démon, rien n'est repris à chaud : la relecture du journal
  d'intention le fait au démarrage (EX-12.15).
- La reprise à chaud et la reprise au démarrage passent par la même
  construction (`_partielReprise`) : classe et origine tirées du nom
  d'outil de l'intention et de la configuration, jamais de la session
  (EX-12.15, lecture 117) ; `_origine` reconnaît le préfixe `<alias>__`
  d'une entrée de `sdk.hosts` avant la règle des serveurs d'outils, et
  `_classe` rend alors `ecriture` (aucune classe configurée, la déclarée
  n'est pas dans le journal d'intention).
- `terminerRelais`, `reprendreRelais` et `scellerEchange` appellent les
  écouteurs de `ecouterScellements` après la durabilité, sans les attendre ;
  `viderAttente` aussi, pour un événement mis en attente avec `host`
  (lecture 125) ; `_reprendreAttente` (démarrage) non, le registre de
  recouvrement n'étant pas reconstruit au redémarrage (EX-6.34).
- `scellerEchange` devient `async` (même contrat) ; le moteur d'échanges du
  frontal modèle (`src/modele/echange.mjs`) lui passe `host: hote.id`, et
  passe `host` et `genre: "echange"` à `mettreEnAttente` ; le frontal MCP
  (`src/mcp/frontal.mjs`, `_mettreEnAttente`) passe `host` et `genre:
  "appel"` à `mettreEnAttente` : seuls changements de modules d'autres lots,
  une ligne chacun.
- `src/cli.mjs` démarre le point d'entrée SDK et l'ingestion après le
  frontal MCP (échec : `demarrage_refuse : sdk` ou `: otel`, code 2), les
  arrête avant le frontal MCP, ajoute `controleSdk` et `controleOtel` aux
  règles du pas 3 d'EX-15.4, et, sans frontal modèle, crée un registre de
  corrélation propre aux échanges déclarés par le SDK, remis aussi au
  frontal MCP (EX-5.22).
- `test/fixtures/enregistreur-coeur/outils.mjs` : `configurationDev` place
  `otel.listen` sur un port libre (`127.0.0.1:0`) et, avec `{ sdk: { hosts } }`,
  active le SDK (prise sous le répertoire du test) et `policy.sdk`.

Ce que le lot suivant (SDK Python et adaptateurs de cadres, 6.4, 6.6) trouve
prêt : le protocole de 6.2 servi tel quel ; `noortrace-sdk/adaptateurs`
(`FileEchanges`, file bornée d'EX-6.11 (3)) pour les points d'observation des
adaptateurs JavaScript ; la classe configurée d'un outil du SDK, que le
schéma v0 ne porte pas (`classeConfigureeSdk` rend `null`, `classeSdk`
applique la règle de la table de 6.2 dès qu'une source existera ; LISEZMOI,
lecture 111). L'exportateur officiel OTLP/HTTP du SDK OpenTelemetry
JavaScript (`@opentelemetry/exporter-trace-otlp-http` 0.223.0, dépendance
d'essai de la racine) est accepté par l'ingestion (parcours de bout en
bout).

## d) Moteur de politique et service d'approbation (§7.5, CT-3)

### Signatures

```js
// côté démon (fait par ce lot)
await coeur.evaluer(requete)                 // EX-7.4, EX-7.16 (validerReponseEvaluer)
await coeur.traiterRemises({ wait_ms })      // message decisions + EX-7.19 pour chaque remise
await coeur.traiterRemise(remise, { held? })  // SG-1 à SG-7 (verifierRemise), décision, acquitter ; held imposé, sinon établi au scellement
await coeur.expirerTickets()                 // EX-9.4, message expiration (réessayé jusqu'à une réponse)
// relecture C : remise et expiration d'un même ticket sérialisées (SG-3 revérifiée sous verrou) ;
// ouvrir, charger, consommer, expiration réessayés jusqu'au succès (délai croissant ≤ 5 s) ;
// consommer : CONCURRENCE_CONSOMMER (4) envois à la fois, au redémarrage seulement si approval.at + E court
ecrivain.signalerPanneStockage(cause)        // panne hors écrivain (fichiers des approbations) : segment fermé, mode « stockage »
coeur.approbations.rouvrir()                 // fichiers des approbations rouverts après un échec d'écriture (fait avant la ligne suivante)
ligneRemise(remise) → ligne | null            // ligne `remise` d'EX-12.23, null si le message ne la forme pas (SG-1)
E_MAX_MS                                      // 86 400 000 : borne de E quand la politique d'une version est introuvable
// interface du service (à implémenter par le vrai service, CT-3 §12)
class ServiceApprobation {
  charger(r); evaluer(r); ouvrir(r); decisions(r); acquitter(r); consommer(r); expiration(r)
}
new ClientServiceApprobation({ url, socket, jeton, timeout_ms, peer_user, tailleMax })  // EX-7.14, EX-18.8
```

### Contrat

- Les sept méthodes rendent l'objet de réponse de CT-3 §12, ou lèvent
  `ErreurServiceApprobation(code, data)` (`code` de CT-3 §12.8, ou
  `indisponible`, `reponse_illisible` — `data.raison: "trop_grande"` au-delà
  de `tailleMax`, 16 Mio par défaut —, ou `pair_non_verifie` : sur la prise
  Unix, propriétaire de la prise différent de `peer_user` ou répertoire de
  la prise inscriptible par d'autres que le compte 0 et `peer_user`,
  EX-18.8, `data.raison` ; vérifié avant chaque message, LISEZMOI lecture
  150). Un 401, et un 5xx `requete_invalide`, donnent `indisponible`
  (`data.statut`, `data.code`) ; le délai `timeout_ms` borne la durée totale
  de l'échange (relecture C).
- Le moteur de politique (lot suivant) décide, d'après la classe, la liste
  des candidats (`coeur.susceptible`), la matrice de 14.2 et le mode
  d'attente, ce que le frontal rend ; il ajoute le mode observation
  (EX-7.23 : `validerReponseEvaluer(r, { observation: true })` est prêt ;
  EX-14.13 à EX-14.17 : marque de `policy.rule` à poser dans la capture).
- La boucle `decisions` tourne avec `minuteurs: true` ; `expirerTickets` est
  appelé à chaque `tic` du cœur, hors mode dégradé, après les événements en
  attente (EX-9.4, EX-9.8).
- Fichiers des approbations (EX-12.23) : écrits par le cœur
  (`coeur.approbations`), relus au démarrage ; le jeu d'une décision pour
  l'exportateur : `coeur.approbations.jeuDecision(evenement)`.
- La validation de `policy.approval.rules` (EX-15.4 pas 3, CT-3 EX-4.2,
  EX-8.2) s'ajoute par `validerConfiguration(octets, { reglesSupplementaires:
  [f] })`, `f(config) → { erreurs, avertissements }`.

### Sections de CT-2 à couvrir

EX-7.4, EX-7.14 à EX-7.23, EX-9.4, EX-12.23, §14.2 (lignes « service
d'approbation »), §14.6, EX-15.4 pas 3 et 6, EX-15.8, EX-18.8 ; CT-3 §7 à
§12.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-3/*` (non rejoués par le cœur) ;
`pieces-mcp/appels/approbation-*` ; `evenements/journal-demo` (seq 5 à 7).

### Mise en œuvre (lot moteur de politique)

Module `src/politique/` (exporté par `@noortrace/enregistreur`) :

```js
import { MoteurPolitique, controlePolitiqueApprobation, validerPolitiqueApprobation,
         regleObservation, REGLE_EVALUATION_IMPOSSIBLE } from "@noortrace/enregistreur";

coeur.politique                         // MoteurPolitique, créé par le constructeur du cœur
await coeur.politique.evaluerAppel(requeteEvaluer, { nom, classe, alias, host, request_id })
  // → { reponse, evaluee, defaut, observation: null | { would, bloquerait } }
coeur.politique.mode                    // "erreur" | "retenir" | "observation" (version en vigueur)
coeur.politique.classeEffective(reponse, classe)      // EX-14.1 (aucun appel soumis en observation)
await coeur.politique.intentionEvaluer(intent)        // membre intent d'EX-7.4 : chaîne, ou texte d'une référence, ou null
coeur.politique.bloquantSansService(nom, classe)      // ligne « service indisponible » de 14.2
coeur.politique.consignerBlocageEvite({ would, raison, alias, nom, classe, seq, host, request_id })
coeur.politique.consignerPerte(raison, nombre, contexte)   // event_lost (EX-14.16)
coeur.politique.instantCapture()        // captured_at, horloge en mode dégradé comprise (EX-14.16)
coeur.politique.ticketsOuverts(), refusEntreeObservation(politique, { depuisMode })   // EX-15.8
coeur.politique.demarrerBoucle({ wait_ms }), arreter()     // boucle decisions (EX-7.19)
validerPolitiqueApprobation(doc, { environment, expire_after_ms }) → [{ code, pointer }]  // CT-3 EX-4.2, EX-8.2
validerConfiguration(octets, { reglesSupplementaires: [controleRedaction, controlePolitiqueApprobation] })
```

- **Pas 3 de 4.4** : `evaluerAppel` appelle `coeur.evaluer` ; hors observation,
  il rend la réponse validée, ou, pour une indisponibilité du service (pas de
  réponse dans `policy.approval.timeout_ms`, erreur de CT-3 §12.8, réponse hors
  d'EX-7.16), la réponse par défaut d'une lecture passante (`autorise`, `rule:
  null`, `approval_default_applied`) si l'outil n'est ni une écriture ni
  susceptible d'approbation et que `policy.failure.approval_service.lecture`
  vaut `passant` ; sinon il lève `ErreurEnregistreur("approbation")`
  (`-31010`). Le frontal MCP applique ensuite les pas 5 et 6 comme avant
  (refus, retenue, signal, rétention).
- **Intention** : le frontal remet à `evaluerAppel` l'intention corrélée telle
  quelle (chaîne, référence de pièce ou `null`) ; le moteur forme le membre
  `intent` d'EX-7.4 (`$defs/requete_evaluer` : chaîne d'au plus 4 096
  caractères ou `null`) : le texte de la pièce pour une référence, `null`
  au-delà de la borne (`intent_not_sent`). Les autres frontaux (SDK) passent
  de même par le moteur.
- **Mode observation** (EX-4.51, EX-7.23, EX-14.13 à EX-14.17) : la réponse
  appliquée est `autorise`, sans ticket, `rule` marquée ` [observation <x>]`
  (ou `evaluation impossible [observation inconnu]`) ; jamais d'exception pour
  le service. Le frontal ne bloque plus pour une panne (stockage, clé, bail
  quand l'instance a été active, horloge, attente), le budget de rédaction ni
  un quota d'hôte : l'appel est relayé, l'événement mis en attente (ou perdu
  au-delà des bornes, `event_lost`) ; une panne après relais rend la réponse
  reçue, jamais `-31017`. Chaque blocage évité donne `observation_would_block`
  (composant `politique`, `seq` de l'événement ou `null`) ; métriques
  `noortrace_observation_mode`, `noortrace_observation_marks_total`,
  `noortrace_observation_would_block_total`, `noortrace_events_lost_total`.
  `-31010 bail_non_detenu`, `-32602` et les autres refus d'EX-14.17 restent.
- **Boucle `decisions`** : démarrée par `Coeur.demarrer({ minuteurs: true })` ;
  relance dès la réponse, délai `wait_ms + timeout_ms`, indisponibilité
  consignée une fois (`approval_service_unavailable`, puis
  `approval_service_available`), nouvel essai à délai croissant (200 ms à
  5 s) ; une réponse vide rendue en moins de 100 ms est relancée après 100 ms.
- **Tic** : `expirerTickets` hors mode dégradé (inchangé) ;
  en mode dégradé, `approval_expired_deferred` une fois par ticket échu.

Changements du cœur faits par ce lot (les plus petits qui complètent le
contrat, avec leurs tests dans `test/enregistreur-politique-exigences.test.js`) :

- `coeur.politique` (constructeur) ; `_armerMinuteurs` démarre la boucle du
  moteur au lieu de la boucle en ligne, `arreter` l'arrête ;
- `coeur.evaluer` borne l'attente du service à `policy.approval.timeout_ms`
  (EX-7.4 : un service muet est une indisponibilité, quel que soit le canal),
  valide avec `{ observation: true }` sous une version en mode observation
  (EX-7.23) et n'y refait pas `evaluer` après `politique_inconnue` (le `charger`
  part sans être attendu, EX-14.15) ;
- `Coeur.demarrer` refuse (`ErreurEnregistreur("politique")`, code 2) d'entrer en
  mode observation avec un ticket ouvert ; `recharger` le refuse
  (`config_reload_rejected`, raison `tickets_ouverts`) et met à jour la jauge
  du mode (EX-15.8) ;
- `tic` vide la file d'attente quand « attente » est la seule raison du mode
  dégradé (elle ne se levait jamais : la file n'était vidée qu'hors de tout mode
  dégradé) et consigne les expirations différées ;
- `tic` constate la sortie du mode dégradé « horloge » (`_sortirHorloge`,
  EX-7.9, EX-7.13, EX-14.11) : elle n'était constatée qu'au scellement
  suivant, qu'aucun appel bloqué ne pouvait produire.

Changements du frontal MCP (`src/mcp/frontal.mjs`), pour brancher le moteur
et la rétention : pas 3 par `coeur.politique.evaluerAppel`, intention remise
telle quelle (le frontal envoyait `null` pour une référence) ; branches du mode
observation ci-dessus ; une ré-émission `en_attente` que le mode `retenir`
retient écrit ses pièces (arguments, contexte) avant d'être retenue, puisque
son relais ou son `refusee` les cite ; l'annulation par l'hôte d'une requête
retenue (`notifications/cancelled`) met fin à la rétention sans réponse
(EX-4.50 : la première ré-émission reconnue qui suit est retenue) ; lignes
`approval_held` et `approval_hold_cancelled`.

`src/cli.mjs` ajoute `controlePolitiqueApprobation` aux règles du pas 3
(démarrage, rechargement, `validate-config`).

## e) Rédaction (§10)

### Où elle s'insère

Avant toute pièce : le frontal remet au rédacteur (`Redacteur`,
`src/redaction.mjs`) la valeur analysée (ou les octets reçus) et la portée
(`arguments`, `resultat`, `requete`, `reponse`, `prompt_systeme`,
`contexte`) ; il reçoit la pièce rédigée de §8, déjà sérialisée et hachée
dans un fil de calcul (`pieceJson`, `pieceTexte`, `pieceNonJson` ou
`pieceNonRedigeable`, EX-8.7), le drapeau `redacted` d'EX-10.16 et, s'il la
demande, la valeur rédigée (gabarits d'effets, intention). Il l'écrit par
`coeur.ecrirePiece`. Le cœur ne rédige rien et ne voit jamais une pièce non
rédigée ; il pose `policy.redaction` (EX-10.20) d'après les références.

### Crochets du cœur

```js
const redaction = Redacteur.depuisConfiguration(config, secrets);   // fils de calcul (EX-3.6), coffre (EX-10.22)
Coeur.demarrer({ ..., redaction, reglesSupplementaires: [controleRedaction] });
// crochets lus par le cœur sur `redaction` (tous facultatifs) :
//   lier(coeur)                                → journal d'exploitation et métriques du cœur
//   redigerMotif(motif) → motif rédigé ou null  // EX-10.24 ; une promesse est attendue
//   executerExtract(motif, texte) → chaîne ou null       // EX-7.6 pas 3 sous EX-10.23, fil appelant
//   evaluerEffets(p) → Promise<{ effets, omis }>          // EX-7.6 entier dans un fil de calcul (EX-3.6)
//   verifierPolitique(politique, politiquesParVersion) → raison ou null   // EX-10.21
//   recharger(config, secrets)                 → après le scellement de l'événement de politique (EX-15.5)
validerConfiguration(octets, { reglesSupplementaires: [controleRedaction] })  // EX-10.6, EX-10.23 op. 4, EX-7.6, EX-10.22
controleSecretsRedaction(config, secrets) → erreurs                          // pas 4 : clé du coffre, 32 octets
```

Changements du cœur faits par ce lot (les plus petits qui complètent le
contrat) : `redigerMotif` est attendu (`await`), ce qui laisse le motif
d'une décision se rédiger dans un fil de calcul ; `terminerRelais` emploie
`redaction.evaluerEffets` s'il existe (l'exécution des `extract` sort du fil
de l'écrivain, EX-3.6), sinon `evaluerEffets` avec `executerExtract` ;
`recharger` passe `reglesSupplementaires` (option de `Coeur.demarrer`) à
`validerConfiguration`, puis appelle `redaction.recharger` ; l'annonce d'une
politique appelle `redaction.verifierPolitique` et lève
`ErreurEnregistreur("politique")` sur refus ; le constructeur appelle
`redaction.lier(coeur)`. Dans `evaluerEffets`, un exécuteur qui lève une
erreur marquée `budget: true` fait omettre l'effet (`budget_redaction`) et,
pour une écriture restée sans effet, déclarer l'effet par défaut (EX-10.23
point 2).

### Rédacteur offert aux frontaux

```js
const r = await redaction.redigerPiece(demande, { id, seq, host });  // EX-10.14, EX-10.16, EX-8.7, EX-10.23 op. 1
// demande :
//   { genre: "json",  portee, outil?, alias?, valeur, origine?, media_type?, content_type?, avecValeur? }
//   { genre: "texte", portee, outil?, alias?, texte, origine? }          // prompt système, intention : text/plain
//   { genre: "octets", portee, outil?, alias?, octets, content_type?, codage_inconnu? }   // corps non JSON (8.3)
//   { genre: "contexte", outil?, alias?, octets, media_type? }           // document de declarerContexte (8.2)
// r : { piece (Piece, référence calculée), valeur? (rédigée), redacted, non_redigeable, comptes }
redaction.redigerArguments(valeur, { outil, alias, id })   // portée arguments, avec la valeur rédigée
redaction.redigerResultat(valeur, { outil, alias, id })    // portée resultat, avec la valeur rédigée
redaction.redigerPromptSysteme(texte)                      // portée prompt_systeme ; prompt_version = r.piece.sha256
redaction.bloquerArgumentsNonRedigeables(r, { classe, susceptible })   // EX-10.23 op. 1 : -31010, raison redaction
await redaction.admettreRunId(v); await redaction.admettreNomPrompt(v); await redaction.admettreValeurLigne(v)
await redaction.redigerEffetsDeclares(effets, { outil, alias })        // EX-6.6
JETON_PROMPT_SYSTEME   // "[REDIGE:prompt-systeme]" (EX-8.5, EX-10.7)
```

- `origine` est la valeur (ou le texte) que la comparaison d'EX-10.16
  emploie quand elle diffère de l'entrée : la requête reçue quand le frontal
  a remplacé le prompt par `JETON_PROMPT_SYSTEME` (mode `reference`, EX-8.5,
  qui compte alors comme une rédaction), le texte d'intention qu'aurait donné
  la réponse en clair (EX-5.21, EX-10.18). Les chaînes porteuses du prompt
  propres à chaque format (EX-8.5, mode `inline`) sont désignées par le
  frontal modèle, qui les rédige par `genre: "texte"`, portée
  `prompt_systeme`, avant la portée `requete`.
- Le rédacteur consigne `redaction_applied` (portée, règles, comptes, l'`id`
  de l'appel avant scellement), `redaction_path_unresolved`,
  `redaction_budget_exceeded` et compte `noortrace_redactions_total`,
  `noortrace_redaction_budget_exceeded_total` ; le frontal consigne
  `delegation_refused` et le refus `-31010` qu'il rend.
- Avec le coffre activé, chaque pièce rédigée a son homologue chiffré avant
  que la promesse soit résolue ; `CoffreOriginaux.dechiffrer` exige deux
  personnes et consigne l'accès (CT-7 EX-3.11).

### Sections de CT-2 à couvrir

§10 en entier (EX-10.1 à EX-10.24), EX-7.2 (détecteurs sur `run_id`), EX-8.5,
EX-8.6, EX-8.7, EX-3.6 (fils de calcul).

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/redaction/*` (le cœur en rejoue la sérialisation de §8
des pièces publiées ; le rédacteur, politiques, motifs et cas entiers) ;
`pieces-mcp/appels/*` (arguments et résultats rédigés) ;
`evenements/journal-demo` (arguments de seq 3, 5, 7 ; prompt système,
requête en mode `reference` et réponse hors flux de seq 2). Rejoués par
`test/enregistreur-redaction.test.js` et, pour l'inventaire,
`test/enregistreur-coeur-vecteurs.test.js`.

## f) WORM (§12.6, §12.11) et haute disponibilité (§13)

### Signatures

```js
class SupportWorm { async copier({ cle, chemin, nature }) → { version_id } }
cleObjetWorm(prefix, cheminRelatif)          // EX-12.16

class MagasinBail {
  get type(); async acquerir() → epoch; valide(); async verifierApresEcriture(); async liberer()
}
```

### Contrat

- L'écrivain appelle `copier` (sans attendre ni bloquer, EX-12.16) pour chaque
  segment fermé (`nature: "segment"`), à chaque clôture pour le manifeste,
  sa signature et la série des points (`manifeste`, `signature`, `points`).
  Le registre des copies (EX-12.29), le contrôle du verrou (EX-12.33), le
  relevé (EX-17.6), le gel (12.11) et `copy_pieces` sont au lot WORM ; une
  copie en échec est consignée (`worm_copy_failed`).
- `acquerir` rend une époque strictement croissante (EX-13.4) ; l'écrivain
  vérifie `valide()` avant chaque fdatasync et chaque signature (EX-13.6) et
  appelle `verifierApresEcriture()` après chaque fdatasync (EX-13.10 (2)) ;
  un bail perdu met le cœur en mode dégradé « bail » : il ne reprend
  qu'après un redémarrage (relecture d'EX-12.10, EX-13.6). Ce lot fournit le
  magasin `file` d'un seul hôte (`MagasinBailFichier` : `flock(2)` pris et
  tenu par un auxiliaire `flock(1)` d'util-linux qui vit tant que le démon
  vit ; `new MagasinBailFichier(chemin, { programme })` ; LISEZMOI, lecture
  148) ; `postgresql`,
  `etcd`, l'attente du bail (`lease_standby`), la bascule (13.4) et
  `lease.fencing` sont au lot de haute disponibilité.

### Sections de CT-2 à couvrir

§12.6 (EX-12.16 à EX-12.18, EX-12.29 à EX-12.33), §12.11 (EX-12.34 à
EX-12.41), §13 en entier, EX-17.5 à EX-17.7.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/worm/*` (non rejoués par le cœur) ;
`evenements/journal-demo/segment.ndjson` (clé de copie de l'exemple
d'EX-12.29).

### Mise en œuvre (lot WORM et haute disponibilité, `src/worm/`, `src/ha/`)

```js
import { supportWormDepuisConfiguration, magasinBailDepuisConfiguration, principalCtl,
         ServiceCopiesWorm, SupervisionWorm, OutilGel, operationsSupport } from "@noortrace/enregistreur";

const worm = supportWormDepuisConfiguration(config, secrets);   // ServiceCopiesWorm (SupportWorm), ou null sans support
const coeur = await Coeur.demarrer({ config, secrets, worm, attendreBail: true, surAttente, ... });
// bail : magasinBailDepuisConfiguration(config, secrets) (file, postgresql, etcd), créé par le cœur s'il n'est pas fourni
await coeur.demarrage;           // avec attendreBail : la promesse se résout à la prise du bail
await principalCtl(["worm", "gel", "poser", ...]);   // bin/noortrace-ctl ; aussi demander-levee, lever, reprendre, etat, et worm releve
await principalCtl(["worm", "reconstruire", "--configuration", f, "--vers", rep]);   // EX-12.17, chemin B de CT-8 ; et worm restaurer <clé> --version <id>
await reconstruireJournal({ config, operations, destination, registre, clePublique });  // synthèse { fichiers, last_seq, last_hash, epoque_max, perdus, ... } ou ErreurRestauration
// clePublique(keyId) : clé initiale du journal (défaut : signataire de classe D de la configuration ;
// noortrace-ctl worm reconstruire --cles <cles.json>) ; les autres clés viennent des rotations de la chaîne
await principalAttributs(["--racine", storageRoot, "--intervalle-s", "60"]);       // bin/noortrace-attributs (compte 0, CAP_LINUX_IMMUTABLE) ; et « sonde »
```

Fonctions sans réseau (rejouées contre `spec/vecteurs/ct-2/worm/`) :
`requeteOperation`, `requeteS3*`, `requeteAzure*`, `requeteGcs*`,
`encoderComposant`, `contentMd5`, `formeRequete` (EX-12.39) ;
`controlerVerrou`, `lireEcheance`, `echeanceMinimale` (EX-12.33) ;
`calculerPerimetre`, `octetsListeObjets` (EX-12.35) ; `verifierGarde`,
`empreinteEnregistrement`, `etatGel`, `versionsALever` (EX-12.37, EX-12.38,
EX-12.40, EX-17.7).

Supports (`operationsSupport(worm, identifiants)`) : `s3-object-lock`
complet (couche d'accès SigV4 écrite sur `node:crypto`, style « path »
avec `endpoint`, « virtual-hosted » sans) : copie, état d'une version,
liste paginée des versions, lecture, écriture conditionnelle, gel,
configuration de verrouillage ; `azure-immutable-blob` et
`gcs-object-retention` : seules les opérations que CT-2 0.5 fixe (gel et
état d'une version, EX-12.39), avec un jeton porteur ; la copie, la liste
des versions, la lecture et l'écriture d'un objet lèvent `ErreurNonFixe`
(LISEZMOI, lecture 84). Identifiants d'une référence de secret : JSON
`{ "access_key_id", "secret_access_key", "session_token"? }` (S3) ou
`{ "bearer_token" }` (Azure, GCS).

Contrôles périodiques : `SupervisionWorm` ne fait plus que ceux propres au
support (SHA-256 des copies de l'heure, balayage, rétention du support,
registre des gels, relevé) ; manifeste, signature, continuité, signataire et
relecture quotidienne des segments fermés sont faits par le cœur, avec ou
sans WORM (`coeur.controles`, rubrique h).

Contrat tenu envers l'écrivain : `ServiceCopiesWorm.copier({ cle, chemin,
nature })` ne rejette jamais ; il consigne lui-même `worm_copy_failed` et
rend `{ version_id: null }` en échec ; les copies sont sérialisées. Il refuse
toute clé hors des sous-préfixes copiés et sous `<prefix>gels/` (EX-12.32),
et un segment d'époque inférieure au dernier scellé (EX-13.5 (2)). Crochets
lus par le cœur sur `o.worm` : `lier(coeur)` (constructeur), `armer()`
(`_armerMinuteurs` : contrôles d'EX-17.5 à EX-17.7, balayage des copies
manquantes), `arreter()`.

Contrat tenu envers le cœur par les magasins réseau (`MagasinBailReseau`) :
`acquerir()` rend une époque strictement croissante ou lève
`ErreurEnregistreur("bail_non_detenu")` (détenu ailleurs) ou `("bail")`
(magasin injoignable au-delà de `acquire_wait_ms`) ; `valide()` sur
l'horloge monotone (`t_renew + ttl_ms − renew_ms`) ; fil de
renouvellement ; une perte (renouvellement refusé, bail échu) consigne
`lease_lost`, met `noortrace_lease_epoch` à 0 et le cœur en mode dégradé
« bail » ; `verifierApresEcriture()` lit le magasin (EX-13.10 (2)) ; crochet
`lier(coeur)`.

Changements du cœur faits par ce lot (les plus petits qui complètent le
contrat, avec leurs tests dans `test/enregistreur-ha-exigences.test.js` et
`test/enregistreur-worm-exigences.test.js`) :

- `Coeur.demarrer` : le magasin vient de `magasinBailDepuisConfiguration`
  (au lieu de « non fourni par ce lot ») et reçoit `lier(coeur)` ; avant
  toute acquisition, la ligne de contrôle de la clé du MAC de relais est
  comparée à celle du dernier fichier `mac-*` (13.4 pas 1) : différence →
  `relay_mac_key_mismatch`, pas de bail (refus, code 2 ; ou attente) ;
  option `attendreBail` : un bail détenu ailleurs donne une instance
  passive (`coeur.passif`, `lease_standby`, `noortrace_lease_epoch` 0,
  supervision servie : `/healthz` `standby`, `/readyz` 503), nouvel essai
  toutes les `renew_ms`, `surAttente(coeur)` appelé une fois ; la promesse
  se résout dès l'état passif, la fin du démarrage est
  `coeur.demarrage` ; l'instance reste passive après la prise du bail
  jusqu'à la fin de la reprise (intentions, attente, événement de
  politique, EX-9.8), puis passe en service (13.4 pas 7) ; sans l'option,
  refus comme avant ;
- en instance passive : `_bloquerSiIntervention` et `evaluer` lèvent
  `ErreurEnregistreur("bail_non_detenu")` (`-31010`, 14.2), `_charger`
  n'envoie rien (le service n'est joint qu'après la prise du bail, 13.4
  pas 6) ;
- `lease_acquired` porte `fencing` (moyen de `lease.fencing`, exécuté par
  l'orchestrateur, EX-13.10 (1)) ; après la relecture, la taille des
  fichiers d'époque inférieure est consignée (`lease_predecessor_files`) et
  `tic` contrôle leur croissance (`journal_fork`, EX-13.10 (3)) ;
- EX-13.5 (1) : l'écrivain refuse d'ouvrir un segment ou son fichier
  d'intention, et le cœur son fichier d'attente (l'événement reste alors en
  mémoire), si une époque supérieure est présente dans les noms des
  fichiers du répertoire du journal, tous sous-répertoires à époque compris
  (`verifierEpoqueOuverture`, `epoqueMaxJournal`) ; avant chaque écriture
  (événement, intention, levée, point, clôture, fichier d'attente),
  `Ecrivain.verifierEcriture(sorte)` (ajout du lot de correction D-1) exige
  le bail valide et aucune époque supérieure présente (`GardeEpoque`) ;
  sinon `lease_lost` (`cause: "epoque_superieure_presente"`), mode dégradé
  « bail », erreur de raison `bail`, et rien n'est écrit ;
- à la reprise d'un fichier d'attente, une ligne dont l'intention est déjà
  levée par un autre événement (reprise) n'est pas scellée
  (`pending_superseded`, EX-4.46) ;
- EX-17.2 : `instanceExploitation(config)` rend `recorder.instance_id` avec
  `postgresql` ou `etcd`, sinon null ; `JournalExploitation` (option
  `instance_id`) et `JournalOutil` de `noortrace-ctl` l'ajoutent à `data`
  de chaque ligne ;
- `etatSante()` porte `passive` ; `_armerMinuteurs` et `arreter` appellent
  `o.worm.armer()` et `o.worm.arreter()` ;
- EX-12.18 : à la reprise des intentions, un fichier d'intention dont tout
  est levé et que le système refuse de supprimer (`EPERM` : attribut `a`
  posé par le compagnon) est gardé et consigné (`intention_file_kept`,
  composant `stockage`) au lieu d'arrêter le démarrage (test
  `test/enregistreur-worm-attributs.test.js`).

Reconstruction (EX-12.17) : `reconstruireJournal` et `restaurerVersion`
(`src/worm/restauration.mjs`) n'écrivent que dans un répertoire neuf
(`<vers>/<org>/<journal>/`, rempli dans un répertoire provisoire renommé à
la fin, supprimé en cas d'échec) ; incidents rendus par `ErreurRestauration`
(`incidents[].kind` : `copie_absente`, `copie_alteree`,
`versions_multiples`, `segment_absent`, `entete_invalide`,
`epoque_decroissante`, `version_non_inscrite`, `lecture_impossible`,
`destination_existante`, `destination_originale`, `cle_refusee`,
`cle_inconnue` ; `raison` précise `copie_alteree` : `signature`,
`hash_different`, `chainage`, `chaine`, `manifeste_recalcule`,
`signature_manifeste`, `continuite`, `serie_points`, `sha256_piece`,
`fin_incomplete`… ; `copie_absente` : `signature_absente`, `serie_absente`)
; le répertoire reconstruit est vérifié en entier par
`verifierRepertoireJournal` (`src/verification.mjs` : signatures avec les
clés de la chaîne, manifestes et leurs signatures, séries, pièces ; LISEZMOI,
lecture 149) ; codes de `noortrace-ctl` : 0 fait, 1 incident, 2 usage ou
destination, 4 support.
Le démon n'a pas d'interface avec la reconstruction : il démarre sur le
répertoire reconstruit et prend une époque plus grande que toutes celles des
noms (13.4).

Compagnon des attributs (EX-12.18, CT-8 EX-3.9) : `passageAttributs(racine)`
et `principalAttributs(argv)` (`src/worm/attributs.mjs`,
`bin/noortrace-attributs`) ; le compagnon ne lit ni la configuration ni une
interface du démon : il déduit le segment courant (le dernier dans l'ordre
des noms, 12.1) et le journal d'intention courant (la plus grande époque)
des seuls noms de fichiers ; le démon ne lui expose rien et ne lui signale
rien (aucun texte ne le prescrit). Événements sur la sortie d'erreur
(NDJSON, composant `stockage`) : `attribute_set`, `attribute_failed`,
`attribute_refused` ; état du dernier passage sous `TMPDIR` pour la sonde.

`src/cli.mjs` : `supportWormDepuisConfiguration`, `attendreBail: true`
(les frontaux s'ouvrent pendant l'attente et rendent `-31010
bail_non_detenu`), règle `controleWorm` au pas 3 d'EX-15.4 (avertissement
si `worm.credentials` est la même référence qu'un autre secret) ; dans
`lancer()`, un échec de la fin du démarrage après l'attente rend le code
2, et un bail perdu (mode dégradé « bail ») relance le démon dans le même
processus, qui relit le journal et redevient passif tant qu'une autre
instance détient le bail (13.4 pas 8, EX-13.6). `package.json` : `bin`
`noortrace-ctl` et `noortrace-attributs`.

## g) Ancrage (CT-5)

### Signature

```js
class ComposantAncrage {
  remettrePoint({ point, checkpointHash, fingerprint, chemin })
  remettreCloture({ manifeste, signature, periodHash, fingerprint, periodMeta,
                    cheminManifeste, cheminSignature, cheminSerie })
}
```

### Contrat

- `remettrePoint` est appelé après l'écriture et la synchronisation de chaque
  point dans `points/periode-<period_start>.ndjson` (EX-12.26, EX-12.27), y
  compris le point de clôture ; `fingerprint = keccak256(org_id ‖ journal_id
  ‖ checkpointHash)`.
- `remettreCloture` est appelé après l'écriture du manifeste et de sa
  signature ; `fingerprint = keccak256(org_id ‖ journal_id ‖ periodHash)` et
  `periodMeta` sont ceux de CT-1 §10.4.
- Le cœur n'attend jamais le résultat (14.2, « Ancrage » et « Registre ») ;
  une erreur est consignée (`anchor_pending`) ; le composant réessaie.
- La cadence (`checkpoint_interval_s`) est dans la configuration et vérifiée
  au démarrage (EX-12.24).

### Sections de CT-2 à couvrir

§12.10 (EX-12.24 à EX-12.28), §14.2 (lignes « Ancrage »), EX-11.13,
EX-11.19 ; CT-5 §8.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-5/*` ; `spec/vecteurs/ct-1/points-de-controle/` (forme des
séries).

### Mise en œuvre (`src/ancrage-demon.mjs`)

Le composant de CT-5 (`@noortrace/ancrage`, dépendance d'espace de travail,
aligné sur CT-5 révision 0.5 et CT-6 révision 0.5) est branché ; la rubrique
F.3 d'`INTERFACES.md` du composant dit ce que l'enregistreur lui fournit,
membre par membre. Signatures :

```js
import { preparerAncrage, BranchementAncrage, ErreurBranchementAncrage,
         resoudreSecretsAncrage, cleChaineDepuisConfiguration, instanceDepuisManifeste,
         FICHIER_INSTANCE_REGISTRE, REPERTOIRE_REGISTRE, CLASSES_CLE_CHAINE_SERVIES } from "@noortrace/enregistreur";

const ancrage = await preparerAncrage({ config, secrets, env, horloge, aleatoire, clients });
// null quand anchoring.ancrage est null ; lève ErreurBranchementAncrage (raison classe_cle_chaine) pour une clé de chaîne de classe A à C
const coeur = await Coeur.demarrer({ config, secrets, ancrage, horloge, ... });   // lier(coeur) après l'écrivain : anchoring_attached
ancrage.etat()                       // état du composant (demarre, arrete, …) + { attached, reason, document, registry }
ancrage.metriques()                  // texte Prometheus d'EX-8.15, concaténé à /metrics par le cœur
await ancrage.recharger()            // à noortrace-ctl reload, après la politique
ancrage.retirerQualification(id)     // EX-5.9
await coeur.exporterDossier(seq, destination)   // par l'exportateur du composant quand il est démarré
await coeur.reexportsDus()           // EX-10.5
await coeur.commandeAncrage({ commande: "etat" | "metriques" | "retirer-qualification", id })
```

- **Démarrage** (`cli.mjs`, avant `Coeur.demarrer`) : document `ancrage-v0`
  lu en JSON strict ; secrets des pointeurs `/rfc3161/providers/<i>/auth/secret`
  et `/opentimestamps/headers_source/auth` résolus par `resoudreSecret`
  (`env`, `file`, `vault`) ; clé de chaîne de `anchoring.registry.chain_key`
  construite (classe D, `SignataireChaineFichier`, adresse confrontée) ;
  manifeste d'instance lu dans `instance-registre.json` à côté du document.
  Une classe A, B ou C refuse le démarrage du démon
  (`demarrage_refuse : ancrage : classe_cle_chaine`, code 2) ; tout autre
  défaut laisse le démon démarrer, `anchoring_not_started` nomme la raison
  (`document_illisible`, `configuration_invalide` et ses règles d'AN-1,
  `secret_non_resolu` et son pointeur, `instance_registre_absente`,
  `rpc_url_absente`, `demarrage_impossible`) et chaque remise donne
  `anchor_pending`. Profil du composant : `production` si
  `recorder.environment` l'est, `developpement` sinon.
- **Contexte** : `org_id`, `journal_id`, époque du bail, `storage.root`,
  `clePublique` (signataire pour la clé courante, index des clés des
  segments pour les autres), `lireSerie` (série relue, lecture seule),
  `lireHashesPeriode` (hashes des événements de la période depuis les
  segments, triés par `seq` ; `BranchementAncrage.segmentsLus`, `Map` de
  chemin → taille, `mtimeMs` et bornes `ts` des événements du segment : un
  segment inchangé dont les bornes sont hors de la période n'est pas relu ;
  `segmentsRelus` compte les relectures), `listerPeriodes` (manifestes et signatures), `listerPoints`,
  `cleChaine`, `instance`, `signaturesCloture` (demande signée
  `<journal>/registre/demande-cloture-<period_hash>.json`, forme
  `demande_signature` de CT-4 vérifiée par `verifierDemande`, sinon `null`
  → `period_close_delegated`). Envois et captures du registre sous
  `<journal>/registre/`.
- **Horloge** : celle du cœur étendue de `programmer` (`setTimeout`, ou la
  minuterie de l'horloge injectée par `principal(argv, { horloge })`) ;
  **aléa** : `crypto.randomBytes` ; **journal** : `JournalExploitation` du
  cœur, composant `ancrage` ; **métriques** : `/metrics` de la supervision
  concatène `ancrage.metriques()`.
- **Cycle dans le cœur** : `lier` après `ecrivain.demarrer` (jamais
  bloquant : une exception est consignée `anchoring_not_started`
  `exception`) ; `recharger` après la politique dans `Coeur.recharger` ;
  `arreter` après `ecrivain.fermer()` (`anchoring_stopped` avant `shutdown`) ;
  `anchoring.ancrage` `null` : `preparerAncrage` rend `null` et rien ne
  change.
- **Export** (`dossier.mjs`) : `assemblerBase` (sept parties de CT-1,
  hashes, indice de feuille, série, manifeste, raisons) puis
  `exportateur.exporterDossier(base, { destination, generated_at })` du
  branchement quand le composant est démarré (treize parties, ancres du
  point couvrant, `entetes-bitcoin.json` à côté, `dossier_exported`) ; sans
  ancrage, l'export de CT-1 §11 du cœur. Le branchement garde, pour
  `reexportsDus`, le résumé du dernier dossier de chaque événement
  (`BranchementAncrage.produits`, `Map` de clé `<hash>:<seq>`, le plus
  récent par `generated_at` ; `dossiersProduits` en rend les valeurs) : la
  mémoire gardée croît avec le nombre d'événements exportés, non avec le
  nombre d'exports, et aucun résumé ne retient le texte
  d'`acquisitions.ndjson` (épreuves de l'étape 5).
- **Copie WORM** (`worm/copies.mjs`, `fichiersACopier`) : `ancres/` et la
  file sous `queue.path` par la règle des fichiers fermés (lecture 93) ;
  `registre/` de même.
- **`noortrace-ctl ancrage etat | metriques | retirer-qualification <id>`**
  (`ctl-demon.mjs`) : fichier de demande `{ demande: "ancrage", commande, id }`
  et SIGURG, réponse au journal (`anchoring_state`, `anchoring_metrics`,
  `provider_qualification_withdrawn`, refus `anchoring_ctl_refused`) ;
  `metriques` lit aussi `/metrics`.
- **Lignes du journal d'exploitation ajoutées** : `anchoring_attached`,
  `anchoring_not_started`, `anchoring_state`, `anchoring_metrics`,
  `anchoring_ctl_refused`, `period_close_request_refused`,
  `dossier_exported` (et celles du composant, CT-5 EX-8.15, composant
  `ancrage`).
- **Essais** : `test/enregistreur-ancrage-parcours.test.js` (TE-12 hors
  réseau public sur un démon réel ; variante sur le réseau de développement,
  en attente quand il n'est pas debout), `test/enregistreur-ancrage-exigences.test.js`
  (`anchoring.ancrage` nul, EX-4.8, TA-41, EX-11.19, EX-4.12, TA-62, AN-43,
  TM-16, export et réexport, TI-17) ; fixtures
  `test/fixtures/enregistreur-ancrage/` (`demon.mjs` : démon réel enfant à
  horloge réglable ; `outils.mjs`).
- **Restes** : clé de chaîne de classe A à C (étape 7) ; rotation d'urgence
  relayée au registre (`registre_non_branche` de `Coeur.rotationUrgence` :
  l'`Envoyeur` du composant n'envoie ni inscription ni révocation, et CT-4
  §7 les fait signer par les approbateurs au seuil ; lecture 202) ; clé
  `anchoring.registry.instance` à inscrire dans CT-2 (lecture 199).

## h) Corrections de la relecture A (cœur, stockage, bail, WORM, haute disponibilité)

Changements du cœur (tests : `test/enregistreur-coeur-reprise.test.js`,
`-config`, `-approbations`, `-journal`, `test/enregistreur-worm-restauration.test.js` ;
lectures 144 à 156 du LISEZMOI) :

```js
coeur.accepterHorloge()          // noortrace-ctl clock --accept (SIGUSR2) → { accepte } | { accepte: false, raison: "hors_mode_horloge" | "recul" }
coeur.controles                  // SupervisionIntegrite (src/controles.mjs) : armer(), arreter(), tic(), horaire(t), quotidien(t)
await verifierRepertoireJournal(rep, { org_id, journal_id, clePublique, dernierOuvert, signatureAbsenteAdmise })
  // → { incidents, evenements, lastSeq, lastHash, cles } (src/verification.mjs)
await principalCtlDemon(["reload" | "clock", "--accept", "--configuration", f])  // bin/noortrace-ctl, codes 0, 1, 2, 4
```

- Écrivain : au démarrage, fichiers `.tmp-*` supprimés, manifeste sans
  signature signé sur ses octets s'il est celui que donne la chaîne (puis
  remise à l'ancrage et copies WORM refaites) ; erreur de `write` ou de
  `fdatasync` : segment tronqué à la longueur du dernier `fdatasync` rendu,
  opérations non couvertes refusées, segment suivant ouvert après la
  troncature ; intention et contexte en une seule écriture, retirées si leur
  `fdatasync` échoue ; au tic, rien n'est clos ni pointé en mode « horloge »
  ou quand le contrôle de saut d'EX-7.13 échoue
  (`ControleurHorloge.controlerAvance(lu)`).
- `relireJournal` rend `manifestesSansSignature` ; `relireSegment` tient une
  ligne de clé inconnue pour une corruption (`cle_inconnue`).
- `Coeur.demarrer` : vérification complète avant d'écrire d'un journal
  reconstruit (segments, aucun `intentions/`) ; arrêt du démarrage après
  `intention_corrompue` ou `intention_irreconstructible` (rien de plus
  n'est écrit) ; reprise de l'attente idempotente (une ligne dont
  l'événement est déjà dans la chaîne n'est pas scellée de nouveau,
  `pending_already_sealed`).
- `creerRepertoire` synchronise le parent de chaque répertoire créé ;
  `nettoyerTemporaires(rep)` ; `PREFIXE_TEMPORAIRE`.
- Règles du pas 3 (`reglesHorsSchema`) : serveurs stdio en production
  (EX-3.5) ; canal du service d'approbation (EX-18.8, CT-3 EX-12.2 : erreur
  dans tous les environnements, lecture 150) ; `controleWorm` compare
  l'emplacement des références de secrets, sans `encoding`.
- `src/cli.mjs` : `peer_user` remis au client du service ; SIGUSR2 →
  `coeur.accepterHorloge()`.

## i) Corrections de la relecture B (frontaux MCP, modèle et SDK)

Changement du cœur (le plus petit qui permet EX-9.7 ; test :
`test/enregistreur-mcp-exigences.test.js`, cas R-B-12 ; lecture 158) :

```js
const desabonner = journal.abonner((ligne) => {}); // JournalExploitation : appelé de façon synchrone pour chaque ligne consignée, erreurs ignorées
```

Contrats complétés des frontaux (tests : `test/enregistreur-mcp-exigences.test.js`,
`-modele-exigences`, `-modele-miroir`, `-sdk-exigences`, blocs « relecture B » ;
lectures 157 à 164 et 173) :

```js
// Frontal MCP (rubrique a)
await frontal.recevoir(s, octets, { cadre, canal, compte: true }); // compte : octets déjà comptés par le transport
canal.statutHttp                    // posé par le frontal pour ses propres erreurs : 404 (méthode inconnue), 400 (meta_requis)
frontal.compterRecus(hote, n)       // octets reçus, comptés par le transport dès leur lecture (4.4 pas 1, EX-4.47)
frontal.compterCapture(hote, ms)    // temps d'analyse d'un transport
frontal.refusAvantAnalyse(hote)     // → texte -31013 (id null) si quota d'octets ou de temps atteint, sinon null
cleIdJson(texte, noeud)             // clé d'un id JSON-RPC par valeur (annulation)

// Prises locales (src/mcp/hote-stdio.mjs), employées aussi par sdk/prise.mjs et modele/miroir.mjs
await ecouterPriseUnix(serveur, chemin, 0o660)   // mode posé dès la création (EX-18.1)
preparerRepertoirePrise(socket)                   // crée (1770) ou refuse un répertoire où un pair renommerait la preuve d'un autre
controlerRepertoirePrise(dir)                     // → raison | null
verifierPreuveFichier(socket, defi, instantDefi)  // → { utilisateur } | { refus, detail? }
PREFIXE_JOURNAL                                   // '{"noortrace_journal":' : ligne du démon vers la sortie d'erreur du connecteur

// Streamable HTTP (src/mcp/hote-http.mjs)
chargeurJwksHttps(uri, { requete, delaiMs, tailleMax })  // une lecture en vol, 10 s et 1 Mio par défaut
decoderEnteteParametre(valeur)                           // sentinelle =?base64?…?= décodée, ou null

// SDK (rubrique c)
await frontal.recevoir(cx, octets, { compte: true }); frontal.compterRecus(hote, n)
```

`subscriptions/listen` d'un hôte moderne (lecture 173) : filtre sous
`params.notifications`, premier message `notifications/subscriptions/acknowledged`
(`{ notifications: { toolsListChanged }, _meta: { "io.modelcontextprotocol/subscriptionId": <id> } }`),
puis `notifications/tools/list_changed` marquées du même id ; en HTTP, le
transport passe la requête au frontal avec son `canal` (flux SSE).

Client `noortrace-sdk` (`paquets/sdk-js/src/index.mjs`) : `_connexionVive()`
fait une seule tentative ; `_ouvrirSession` compte les reprises, au plus
`1 + reprises` connexions en tout (EX-6.13).

Protocole de la prise des connecteurs : après `{"noortrace_identite":"acceptee"}`,
le démon peut envoyer des lignes `{"noortrace_journal":<ligne>}` que le
connecteur écrit sur sa sortie d'erreur (EX-9.7). Les échecs de jeton du
Streamable HTTP, de la prise TCP des connecteurs et de la passerelle sont
limités par `LimiteurEchecs` (`reason: "jeton_limite"`, EX-18.3).

## j) Signataires des classes A, B et C (§11)

Lot « signataires » (`src/signataires/`). Chaque backend étend `Signataire`
(`clePublique`, `signer`, `sante`, `clesConnues`, `effacer`, EX-11.18) et
ajoute `localisation(keyId)` (identifiant non secret chez le backend,
consigné) ; l'enveloppe commune `SignataireVerifie` (borne, délai, seconde
tentative, vérification d'EX-11.6) est inchangée.

```js
import { signataireDepuisConfiguration, SignatairePkcs11, SignataireTransit, SignataireAwsKms,
         SignataireCloudKms, SignataireEnveloppe, desceller, ErreurSignataire } from "@noortrace/enregistreur";

const backend = await signataireDepuisConfiguration(config, secrets, { env, ca });   // classes A à D selon signer.backend.type
// A : pkcs11 (auxiliaire python3 -I -S src/signataires/pkcs11-auxiliaire.py, PIN par stdin)
// B : vault-transit, openbao-transit (X-Vault-Token), aws-kms (SigV4, AWS_*), gcp-kms (compte de service)
// C : envelope + wrap aws-kms | gcp-kms | azure-keyvault | tpm2 (graine de 32 octets en mémoire, effacée à l'arrêt)
```

Changements du cœur (les plus petits qui branchent le lot ; tests :
`test/enregistreur-signataires-exigences.test.js`, `-parcours`) :

- `Coeur.demarrer` construit le backend par `signataireDepuisConfiguration`
  (option `env` : environnement du démon, que `cli.mjs` passe) ; une erreur
  du backend au pas 5 est une `ErreurEnregistreur("cle")`
  (`demarrage_refuse : cle : …`, code 2) ;
- après la clé publique, comparaison avec la clé qu'annonce la chaîne pour
  la clé courante (`signer_key_mismatch`, refus), signature de test, puis
  ligne `signer_ready` { `class`, `backend`, `key_id`, `backend_key`,
  `pkcs11` } (EX-11.8, lecture 183) ;
- `tic()` : `health()` toutes les `signer.health_interval_ms` (échec →
  `signer_unavailable` et mode dégradé « clé », EX-11.18, 14.2) ; rotation
  planifiée (`planned_every_days` écoulés depuis l'entrée en vigueur de la
  clé courante, clé `next_key_id` détenue : `tournerCle`, sinon
  `key_rotation_unavailable` une fois ; EX-11.15, lecture 184).

Compléments (reprise du lot) :

```js
import { lireSecretsVault, IdentiteAws, JetonMetadonneesGoogle, rapprocher, principalRapprochement } from "@noortrace/enregistreur";

const lus = await lireSecretsVault(config, { env, ca });          // références { vault } (15.2), avant le pas 4
const s = resoudreSecrets(config, { env, vault: lus.valeurs });   // resoudreSecret lit contexte.vault pour { vault }
await coeur.rotationUrgence();   // → { accepte, raison?, evenement? } ; noortrace-ctl cle rotation-urgence (SIGURG + demande écrite)
```

- `cli.mjs` lit les références `{ vault }` avant `resoudreSecrets` ;
  `coeur.recharger` aussi ; `lancer()` traite SIGURG (demande
  `<ops_log.path>.rotation-urgence` exigée, lecture 194) ;
- `SignataireVerifie` consigne `signer_test_signature` et ajoute `key_id`,
  `tentatives` à `signer_unavailable` (rapprochement, lecture 195) ;
- `ClientKms` prend son identité d'`IdentiteAws` (variables, ou IMDSv2) ;
  `ClientCloudKms` de `JetonGoogle` (fichier de compte de service) ou de
  `JetonMetadonneesGoogle` (lecture 193).
