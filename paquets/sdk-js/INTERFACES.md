# Interfaces de noortrace-sdk

Ce document s'adresse aux auteurs des adaptateurs de cadres (CT-2 6.6, lot
suivant) et à ceux qui raccordent un agent Node.js. Avec CT-2 6.2 et 6.5, il
suffit.

## Interface publique (EX-6.9), et seulement elle

```ts
import { ClientNoortrace, Session, AppelNonAutorise, ErreurNoortrace, ErreurNoortraceIndisponible,
  ErreurNoortraceDegrade, ErreurNoortraceLimite, ErreurNoortraceNonDurable, ErreurNoortraceEntreeInvalide,
  ErreurNoortraceConfiguration } from "noortrace-sdk";

new ClientNoortrace({ socket?, tcp?, jeton?, delaiMs = 30000, reprises = 2, surIndisponibiliteLecture = "bloquer" })
ClientNoortrace.depuisEnvironnement()
client.ouvrir({ runId?, onBehalfOf? }): Promise<Session>
session.declarerContexte({ kind, octets, mediaType? }): Promise<{ sha256, length, redacted }>
session.debutAppel({ tool, arguments, classe?, contexte?, intent?, effects? }): Promise<{ call, decision, ticket, ticket_state }>
session.finAppel(debut, { resultat?, isError, durationMs }): Promise<{ seq, hash }>
session.appelOutil({ tool, arguments, classe?, contexte?, intent?, effects? }, fonction): Promise<T>
session.echangeModele({ format, providerLabel, request, response, status?, durationMs, isError }): Promise<{ seq, hash }>
session.fermer(): Promise<{}>
```

- Les paramètres portent les noms et les valeurs de 6.2, en camelCase, sauf
  `classe`, `contexte` et `resultat` (`class`, `context`, `result`) ; le SDK
  n'ajoute ni méthode ni paramètre au protocole.
- `{ seq: null, hash: null }` : l'événement est en attente du mode dégradé
  (CT-2 14.5, 14.6) ; il sera scellé à la sortie du mode dégradé (lecture du
  LISEZMOI de `@noortrace/enregistreur`).
- `appelOutil` : `AppelNonAutorise` sans exécuter `fonction` pour toute
  décision autre que `autorise` ; durée sur l'horloge monotone ; résultat non
  JSON rendu `{"noortrace_sdk_non_json": "<type>"}` ; exception de `fonction`
  rendue `{"noortrace_sdk_exception": "<classe>"}`, `isError: true`, puis
  relancée ; son message n'est jamais transmis.

## Pour les adaptateurs (6.6)

```ts
import { FileEchanges } from "noortrace-sdk/adaptateurs";
const file = new FileEchanges(session, { fileMax: 1000 });
file.ajouter({ format: "autre", providerLabel, request, response, status, durationMs, isError });   // ne bloque ni ne lève
file.echangesPerdus                                                                              // compteur d'EX-6.11 (3)
```

Un adaptateur n'appelle `debutAppel` et `finAppel` que depuis un point
d'interception (EX-6.16) ; `FileEchanges` ne sert qu'aux échanges de modèle
observés depuis un point d'observation, jamais à un appel d'outil (EX-6.11).
Les textes rendus au modèle quand l'outil n'est pas exécuté (EX-6.19) se
tirent des erreurs : `AppelNonAutorise.texte`, et les textes fixes d'EX-6.19
pour `ErreurNoortraceDegrade`, `ErreurNoortraceIndisponible`,
`ErreurNoortraceLimite`, `ErreurNoortraceEntreeInvalide`, et, après
l'exécution, `ErreurNoortraceNonDurable` ou `ErreurNoortraceIndisponible`.

## Adaptateurs de cadres (6.6)

```ts
import { intercepter, texteAvantExecution, nomDeclarable, valeurDeclaree, reglagesAdaptateur, etiquette,
  TEXTE_DEGRADE, TEXTE_INJOIGNABLE, TEXTE_LIMITE, TEXTE_ENTREE_INVALIDE, TEXTE_NON_DURABLE } from "noortrace-sdk/adaptateurs";
const issue = await intercepter(session, preparer, executer, declarer);
// preparer() -> { nom, args, classe } ; executer() -> Promise<valeur> ; declarer(valeur) -> { resultat, isError }
// issue.executee, issue.texte (texte d'EX-6.19 à rendre au modèle, ou null), issue.valeur

import { middlewareNoortrace, GestionnaireEchangesNoortrace } from "noortrace-sdk/adaptateurs/langchain";
const mw = middlewareNoortrace(session, { classes: { preparer_paiement: "ecriture" }, modele: "passerelle", ignorer: [] });
createAgent({ model, tools, middleware: [..., mw] });          // en dernier ; mw.rappels avec modele: "declarer"

import { adaptateurAgentsOpenAI, ProcesseurEchangesNoortrace, argumentsDeclares } from "noortrace-sdk/adaptateurs/openai-agents";
const a = adaptateurAgentsOpenAI(session, { classes, modele, ignorer });
tool({ name: "preparer_paiement", parameters, execute: a.envelopperExecution("preparer_paiement", execute) });
addTraceProcessor(a.processeur);                                // modele: "declarer" seulement
```

`langchain` 1.5.19 et `@langchain/core` 1.3.0 sont des dépendances pairs
facultatives : seul `noortrace-sdk/adaptateurs/langchain` les importe.
