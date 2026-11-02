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
});
```

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
  d'EX-14.9 (`ErreurEnregistreur("attente")`).

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
dans `NOORTRACE_CONNECTEUR_JETON`) est le connecteur stdio de 19.5.

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

`traiterRemises` passe `held: retient(ticket)` à `traiterRemise`
(`acquitter.held`, EX-7.19) ; après une décision scellée (remise, ou
expiration par le noyau seul), `decidee` est appelé sans être attendu ;
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

## d) Moteur de politique et service d'approbation (§7.5, CT-3)

### Signatures

```js
// côté démon (fait par ce lot)
await coeur.evaluer(requete)                 // EX-7.4, EX-7.16 (validerReponseEvaluer)
await coeur.traiterRemises({ wait_ms })      // message decisions + EX-7.19 pour chaque remise
await coeur.traiterRemise(remise, { held })  // SG-1 à SG-7 (verifierRemise), décision, acquitter
await coeur.expirerTickets()                 // EX-9.4, message expiration
// interface du service (à implémenter par le vrai service, CT-3 §12)
class ServiceApprobation {
  charger(r); evaluer(r); ouvrir(r); decisions(r); acquitter(r); consommer(r); expiration(r)
}
new ClientServiceApprobation({ url, socket, jeton, timeout_ms })  // EX-7.14
```

### Contrat

- Les sept méthodes rendent l'objet de réponse de CT-3 §12, ou lèvent
  `ErreurServiceApprobation(code, data)` (`code` de CT-3 §12.8, ou
  `indisponible`, `reponse_illisible`).
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
  magasin `file` d'un seul hôte (`MagasinBailFichier`) ; `postgresql`,
  `etcd`, l'attente du bail (`lease_standby`), la bascule (13.4) et
  `lease.fencing` sont au lot de haute disponibilité.

### Sections de CT-2 à couvrir

§12.6 (EX-12.16 à EX-12.18, EX-12.29 à EX-12.33), §12.11 (EX-12.34 à
EX-12.41), §13 en entier, EX-17.5 à EX-17.7.

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/worm/*` (non rejoués par le cœur) ;
`evenements/journal-demo/segment.ndjson` (clé de copie de l'exemple
d'EX-12.29).

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
