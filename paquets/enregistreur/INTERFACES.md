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
  redaction,           // { redigerMotif, executerExtract } (section e)
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

## e) Rédaction (§10)

### Où elle s'insère

Avant toute pièce : le frontal remet au rédacteur la valeur analysée et la
portée (`arguments`, `resultat`, `requete`, `reponse`, `prompt_systeme`,
`contexte`), reçoit la valeur rédigée et le drapeau « une règle a joué », puis
construit la pièce par `pieceJson(valeur, { redacted })`, `pieceTexte(texte,
{ redacted })`, `pieceNonJson(octets, { content_type, redacted })` ou
`pieceNonRedigeable({ content_type, length, reason })` (EX-8.7). Le cœur ne
rédige rien et ne voit jamais une pièce non rédigée ; il pose
`policy.redaction` (EX-10.20) d'après les références.

### Crochets du cœur

```js
Coeur.demarrer({ ..., redaction: {
  redigerMotif(motif) → motif rédigé ou null,                 // EX-10.24, motif d'une décision
  executerExtract(motif, texte) → correspondance ou null,     // EX-7.6 pas 3 sous EX-10.23
}})
validerConfiguration(octets, { reglesSupplementaires: [controleRedaction] })  // EX-10.6, EX-10.23 op. 4
```

`evaluerEffets({ ..., sourceNonRedigeable: true })` applique EX-10.23 point 2
(effet par défaut d'une écriture dont une pièce source est non rédigeable).

### Sections de CT-2 à couvrir

§10 en entier (EX-10.1 à EX-10.24), EX-7.2 (détecteurs sur `run_id`), EX-8.5,
EX-8.6, EX-8.7, EX-3.6 (fils de calcul).

### Vecteurs qui l'exercent

`spec/vecteurs/ct-2/redaction/*` (le cœur en rejoue la sérialisation de §8
des pièces publiées) ; `pieces-mcp/appels/*` (arguments rédigés).

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
