# Bibliothèque de la console (`src/bibliotheque/`)

Bibliothèque commune à la page de la console, au serveur de console et au
service d'approbation (contrat `paquets/console/INTERFACES.md`, section 1 ;
CT-3 EX-13.32, hors fichier de clé : le parcours d n'est pas offert). Modules
ECMAScript qui s'exécutent à l'identique sous Node 22 et dans Chromium.

- `@noortrace/console` → `index.mjs` : tous les exports de la section 1, et
  les exports en plus nommés plus bas.
- `@noortrace/console/annuaire` → `annuaire.mjs` : le module d'annuaire
  (table 1.3), seule implémentation des règles de l'annuaire (CT-3 13.3 à
  13.8).

Aucun fichier n'est repris de noorchain-core.

## Modules

Tous sont atteignables depuis `index.mjs` (la carte d'importation des pages
les nomme tous) :

| Module | Contenu | Règles |
|---|---|---|
| `index.mjs` | réexports | EX-13.32 |
| `annuaire.mjs` | module d'annuaire (table 1.3) | EX-13.7 à EX-13.19, EX-13.37, EX-13.38, EX-12.13 à EX-12.19 |
| `identite.mjs` | identité de session | EX-13.7 |
| `message.mjs` | message d'inscription | EX-13.12 |
| `formes.mjs` | contrôle de forme des requêtes du canal (1.2) | EX-12.13 |
| `signatures.mjs` | EIP-191, `personal_sign`, normalisation, recouvrement | EX-9.3, EX-9.21, EX-9.22, EX-13.12, EX-13.16, EX-13.24 |
| `portefeuille.mjs` | codes EIP-1193, réponse, comptes, attente, corps de `voter` | EX-9.21, EX-13.23, EX-13.29, EX-13.30, EX-12.16 |
| `condenses.mjs` | hachage d'un événement, condensés, empreinte, groupes | CT-1 §6.1, §6.3 ; EX-9.17 à EX-9.19 |
| `modele.mjs` | modèle d'affichage, session du modèle | EX-9.4, EX-9.6, EX-9.15, EX-9.16, EX-12.14 |
| `decouverte.mjs` | découverte EIP-6963 | EX-13.22 |
| `constantes.mjs` | `METHODES_CANAL`, `METHODES_REAUTHENTIFICATION`, `CODES_CONSOLE` | EX-12.13, EX-13.8, 13.14 |
| `json.mjs` | JSON strict, JCS v0, égalité JSON, copie | CT-1 §4, EX-9.6 |
| `instants.mjs` | instants de CT-1 §3 | CT-1 §3 |
| `octets.mjs` | hexadécimal, UTF-8, base64 | CT-1 §3, EX-9.15 (3), EX-9.19 |
| `hachage.mjs` | SHA-256, Keccak-256 (@noble/hashes) | CT-1 §6 |
| `erreurs.mjs` | `ErreurConsole` | contrat 0.4 |

Importations : modules relatifs de ce répertoire, `@noble/hashes/sha2.js`,
`@noble/hashes/sha3.js` et `@noble/curves/secp256k1.js` (2.4.0) ; ni
`node:*`, ni `@noortrace/*`, ni DOM, ni horloge, ni réseau, ni état global
mutable. L'aléa (identifiant d'entrée de 64 bits, nonce de 128 bits) vient
de `globalThis.crypto.getRandomValues` seulement.

## Exports en plus

En plus des noms des tables 1.3 à 1.5, `@noortrace/console` exporte (aucune
autre partie n'en dépend sans que le contrat les nomme) :

| Export | Rend |
|---|---|
| `formeRequete(methode, requete)` | vrai si la requête a la forme exacte du `$defs` de la table d'EX-12.13 pour cette méthode (quatorze méthodes) |
| `DEFINITION_REQUETE` | méthode → référence `<$id>#/$defs/<nom>` de sa requête |
| `egaliteJson(a, b)`, `cloner(v)` | égalité de valeurs JSON de CT-1 ; copie profonde |
| `sha256(octets)`, `keccak256(octets)` | 32 octets |
| `versHex`, `depuisHex`, `utf8`, `concatener`, `estUtf8`, `decoderBase64` | conversions d'octets (`utf8` rend `null` pour une chaîne à substitut isolé ; `decoderBase64`, la forme canonique de la RFC 4648 §4 seulement, sinon `null`) |
| `decoderInstant`, `encoderInstant`, `estInstant` | instants de CT-1 §3 ↔ millisecondes |
| `N_SECP256K1` | ordre de secp256k1 (`BigInt`) |
| `feuilles(valeur)`, `resoudrePointeur(valeur, pointeur)` | feuilles d'EX-9.16 ; résolution d'EX-4.4, pas 1 et 2 |

## Lectures du contrat et de CT-3

Chaque choix ci-dessous est éprouvé par `test/exploitation-console-bibliotheque.test.js`.

**Erreurs.** Paramètre d'un autre type, instant hors de CT-1 §3 (motif ou
date absente du calendrier), méthode ou option inconnue : `TypeError`.
`ErreurConsole.detail` vaut le code quand il n'est pas donné ; tous les
détails sont en ASCII. `jcs` lève `TypeError` pour une valeur hors de JCS v0,
y compris au-delà de 128 conteneurs imbriqués (CT-1 §4, règle 7).
`analyserJsonStrict` lit sans borne de profondeur (lecture itérative) et
refuse en plus un nombre hors de la double précision et la marque d'ordre
d'octets.

**Annuaire.**
- `controleCanal` rend `requete_invalide` pour un corps hors de la forme de
  son `$defs` (1.2 lui confie ce contrôle ; la table 1.3 ne nomme pas cette
  raison) : question posée dans le rapport de l'étape.
- `appliquerOperation` rend le même objet annuaire en cas de refus et pour
  `preparer_inscription` accepté (le défi ne change pas l'annuaire) ; un
  nouveau défi pour la même identité et la même adresse retire l'ancien,
  présenté ou non, et s'ajoute à la fin du tableau.
- `verifierInscription`, pas 10 : le texte du défi est reconstruit de ses
  champs ; des champs hors de leur grammaire donnent `message_invalide`.
- Identifiant `compteur` déjà attribué (convention des vecteurs) : `TypeError`.
- `actionRetrait` ne rend le `launched_by` que pour l'entrée active de la
  session, comme le contrôle du service (EX-12.19).
- `controleVote` porte `separation_incomplete` quel que soit le sort et
  l'action ; adresses triées, sans doublon.
- `controleDefi` : réponse qui n'a pas exactement `fields` et `message`, ou
  champs hors de leur grammaire : `message_invalide` ; l'adresse choisie est
  comparée telle quelle.
- `verifierAnnuaireExporte` : sans `conforme`, un contrôle minimal de parcours
  rend `schema` pour un document qui ne se parcourt pas. Point 2 : écarts sur
  `/revision`, `/updated_at` (nul sans opération), `/operations/<j>/seq` et
  `/operations/<j>/at`. Point 4 : un message qui ne s'analyse pas donne
  `preuve_invalide` seul ; sinon `preuve_invalide` (signature non canonique
  ou qui ne recouvre pas l'adresse) et `preuve_discordante` se jugent l'un
  indépendamment de l'autre. Point 6 : le rejeu s'arrête à la première
  opération qui ne se rejoue pas ; une inscription rejouée garde la signature
  normalisée et reçoit `received_at` égal à l'instant de l'opération (effet
  d'EX-13.15) ; l'entrée qui reçoit l'adresse doit avoir l'identifiant
  `entry` de l'opération (une entrée créée ne peut pas prendre un identifiant
  déjà rejoué) ; une opération dont un membre que sa méthode ne porte pas
  n'est pas nul ne se rejoue pas.

**Signatures et portefeuille.**
- `verifierSignature` lit la signature en casse indifférente, rend la forme
  normalisée seulement quand elle est valide, et `recovered` nul aussi quand
  le recouvrement est impossible ; l'adresse attendue est comparée telle
  quelle.
- `requetePersonalSign` exige des données en hexadécimal minuscule et écrit
  l'adresse en minuscules ; `requeteVoter` prend le ticket de `vue.ticket` et
  écrit l'adresse en minuscules.
- `codeErreurPortefeuille` rend `erreur_portefeuille` pour toute valeur qui
  n'a pas l'un des cinq codes numériques ; `analyserComptes` garde l'ordre et
  les doublons, et rend `[]` pour un tableau vide.
- `echeanceAttente` rend la différence brute (négative après l'échéance).

**Modèle d'affichage.**
- Contrôle 2 : les membres `org_id` et `journal_id` de l'événement doivent
  être des chaînes (A en est formé).
- Contrôle 3 : base64 canonique seulement ; sans pièce, la valeur en ligne
  `value` de la référence doit vérifier `sha256` et `length` de son JCS.
- Contrôle 4 : l'intention n'est comparée que si l'événement la porte en
  chaîne.
- `separation_banner` (et `separation_non_verifiable`) : `self_approval`
  `interdite` et `requester_declared` faux ; `separation_incomplete` : une
  adresse de `requester_directory_addresses` absente de
  `requester_addresses`, quel que soit `self_approval`.
- `remaining_ms` : différence brute, négative après l'échéance.

**Découverte.** `uuid` de version 4 et de variante RFC (`[89ab]`), lu en
casse indifférente, deux annonces dont les `uuid` ne diffèrent que par la
casse désignant le même `uuid` ; nom de 1 à 64 points de code ; annonces
écartées rendues par indice croissant ; `lancer()` pose l'écouteur une seule
fois et émet `eip6963:requestProvider` à chaque appel ; `surChangement`
appelle ses fonctions sans argument ; une annonce dont la lecture lève est
`annonce_invalide`.

## Écarts

Aucun écart aux vecteurs (familles `annuaire/` et `console/`, hors
`fichiers-cle/`, en attente : parcours d non offert), sous Node et dans
Chromium.

## Essais

```text
npx mocha test/exploitation-console-bibliotheque.test.js
npx mocha test/exploitation-console-bibliotheque-chromium.test.js
NOORTRACE_EXIGER_CHROMIUM=1 npx mocha test/exploitation-console-bibliotheque-chromium.test.js
```

L'essai Chromium (Playwright 1.56.1, installé sans être ajouté à
`package.json`) sert la bibliothèque, la fermeture de ses importations
`@noble/*` (quinze fichiers, trouvés par l'analyse lexicale du générateur
des pages, commentaires écartés : la carte égale les modules que Chromium
charge), l'exécuteur de cas et une page d'essai depuis
`test/fixtures/exploitation-console/bibliotheque/` à une origine HTTPS fictive,
sous les en-têtes d'EX-13.35 et une carte d'importation à intégrité.
