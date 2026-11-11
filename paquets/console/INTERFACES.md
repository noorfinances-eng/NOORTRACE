# Interfaces de la console d'exploitation (CT-3 §13, révision 0.5)

Ce document est le contrat de l'étape 6 pour le paquet `@noortrace/console` :
la bibliothèque de la console (section 1), le serveur de console (section 2)
et les pages (section 3). Il s'adresse à ceux qui écrivent ces trois parties,
au service d'approbation, qui importe le module d'annuaire de la
bibliothèque, et à l'assemblage de l'étape. Avec CT-3 (sections 9, 10.3,
12.9 et 13), les schémas `console-approbation-v0`, `console-service-v0`,
`annuaire-approbateurs-v0`, `configuration-console-v0` et
`configuration-approbation-v0`, et les vecteurs de `spec/vecteurs/ct-3`
(familles `annuaire/` et `console/`), il suffit.

La console de référence de CT-3 13.15 (`console/`, `scripts/lib/console.mjs`)
n'est ni lue ni importée : ce paquet en satisfait les exigences (EX-13.31 à
EX-13.36), il n'en reprend pas le code. Les modules de curators-hub que CT-3
13.1 dit « repris » (jeton de session signé, garde d'hôte, thème, libellés)
le sont comme patrons ; aucun fichier n'est recopié de noorchain-core à ce
jour, et toute recopie future est inscrite dans `LISEZMOI.md`.

Décisions du porteur qui fondent ce contrat : serveur Node (`node:http`,
`node:https`) sans cadriciel et pages statiques à intégrité ; parcours de
signature a et b seulement (EX-13.20 : c n'est pas activé, d n'est pas
offert) ; interface en français, avec un mécanisme de libellés qui admettra
l'anglais ; OIDC, et système local refusé en production ; aucune marque.

## 0. Règles communes

### 0.1 Arborescence

```text
paquets/console/
  package.json            @noortrace/console (fixé par l'étape 6, voir 0.2)
  LISEZMOI.md             rôle, état, fichiers repris
  INTERFACES.md           ce contrat
  bin/
    noortrace-console     ligne de commande du serveur (2.1)
  schemas/                copies à l'identique de spec/schemas lues par le serveur (2.3)
  src/
    bibliotheque/         bibliothèque commune à la page et au service (section 1)
      index.mjs           réexporte chaque export de la section 1
      annuaire.mjs        module d'annuaire (1.3), exporté aussi par « @noortrace/console/annuaire »
      LISEZMOI.md         lectures et écarts propres à la bibliothèque
      …                   autres modules, au choix de la bibliothèque (1.5)
    serveur/              serveur de console, Node seulement (section 2)
      index.mjs           exports de 2.2
      LISEZMOI.md         lectures et écarts propres au serveur
      …
    pages/                pages de la console (section 3)
      construire.mjs      générateur des écrans et du manifeste (3.3)
      manifeste.json      produit par construire.mjs, versionné
      ecrans/             tickets.html, ticket.html, inscription.html, annuaire.html, connexion.html (produits, versionnés)
      statique/           feuille de style, modules des écrans, libellés (servis sous /statique/)
      LISEZMOI.md         lectures et écarts propres aux pages
```

Chaque partie n'écrit que dans son répertoire ; `package.json`,
`INTERFACES.md` et `LISEZMOI.md` à la racine du paquet ne changent qu'à
l'assemblage de l'étape. Un écart au contrat se signale, il ne s'écrit pas
ici en cours de route.

### 0.2 Paquet et dépendances

`package.json` est fixé par l'étape 6 et ne change pas avant l'assemblage :
`exports` `"."` (bibliothèque), `"./annuaire"` (module d'annuaire),
`"./serveur"` (serveur), `"./package.json"` ; `bin` `noortrace-console` ;
dépendances à version exacte :

| Dépendance | Version | Qui l'emploie | Raison |
|---|---|---|---|
| `@noble/hashes` | 2.4.0 | bibliothèque | Keccak-256 et SHA-256 dans la page et sous Node, sans module natif ; déjà dans l'arbre (`@noortrace/noyau`) ; licence MIT |
| `@noble/curves` | 2.4.0 | bibliothèque | recouvrement secp256k1 (EIP-191) ; déjà dans l'arbre ; licence MIT. La racine du dépôt porte `@noble/curves` 1.9.0 (dépendance d'outils de développement) : sans cette déclaration, Node résoudrait la bibliothèque contre la 1.9.0, et la page contre une autre version que celle des essais |
| `@noortrace/approbation` | 0.1.0 (espace de travail) | serveur seulement | `RegistreSchemas` et `lireJsonStrict`, existants et stables (2.3) |

Le serveur n'a aucune dépendance tierce : `node:crypto` vérifie RS256
(`RSA-SHA256`, PKCS #1 v1.5), PS256 (`RSA-PSS`, sel de 32 octets, SHA-256)
et ES256 (`dsaEncoding: "ieee-p1363"`, les 64 octets `R ‖ S` d'EX-13.46),
calcule scrypt (EX-13.47), HMAC-SHA256 et AES-256-GCM (EX-13.48) ; les clés
JWK s'importent par `crypto.createPublicKey({ key, format: "jwk" })`.
Aucune bibliothèque OIDC, JWT ou HTTP n'est ajoutée.

`@noortrace/approbation` dépend en retour de `@noortrace/console` (module
d'annuaire, 1.3). Les deux liens d'espace de travail forment un cycle au
niveau des paquets, admis à cette seule condition, qui exclut tout cycle
entre modules : `src/bibliotheque/` n'importe jamais `@noortrace/approbation`
ni `node:*` ; le service n'importe de ce paquet que `@noortrace/console/annuaire`
(et, au besoin, `@noortrace/console`, la bibliothèque) ; seul `src/serveur/`
importe `@noortrace/approbation`, et seulement `RegistreSchemas` et
`lireJsonStrict`.

### 0.3 Ce que le paquet ne fait jamais

- recevoir, détenir, dériver ou transmettre une clé d'approbateur (EX-13.1) ;
  aucune route, aucune fonction n'a de paramètre qui en porte ;
- signer quoi que ce soit : la page demande `personal_sign` au portefeuille
  (EX-13.24), la bibliothèque vérifie et recouvre, elle ne signe pas ;
- lire `window.ethereum` (EX-13.22, point 7 : la console d'exploitation ne
  propose pas l'entrée « fournisseur non annoncé ») ;
- livrer une notification (EX-13.39) ou exporter un dossier (CT-2 §15.7) ;
- écrire sur disque (le conteneur `console` n'a qu'un tmpfs, CT-8) : les
  sessions, les transactions et les compteurs du système local sont en
  mémoire ; le serveur écrit son journal sur sa sortie d'erreur (2.13) ;
- employer une marque, une police téléchargée, une ressource d'une autre
  origine.

### 0.4 Conventions de valeurs

- Instant : chaîne horodatage de CT-1 §3 (`AAAA-MM-JJTHH:MM:SS.mmmZ`) ;
  aucune fonction de la bibliothèque ne lit l'horloge : un instant est
  toujours un paramètre.
- Adresse : `0x` et 40 chiffres hexadécimaux minuscules ; les entrées en
  casse mixte sont refusées là où le texte le dit, et ramenées en minuscules
  là où il le dit (EX-13.23, EX-13.18).
- Condensé : `0x` et 64 chiffres hexadécimaux minuscules ; octets :
  `Uint8Array`.
- Annuaire : le document `annuaire-approbateurs-v0` lui-même (objet JSON),
  jamais une classe ; les fonctions de la bibliothèque ne le modifient pas
  et rendent un nouveau document.
- Erreur : un refus de domaine est rendu dans la valeur de retour quand la
  ligne de la fonction le dit (`{ accepted, reason }`, `null` ou un code) ;
  sinon la fonction lève `ErreurConsole`, de membre `code` (une valeur de
  `$defs/code_console` de `console-approbation-v0`, de
  `$defs/code_erreur_annuaire` d'`annuaire-approbateurs-v0`, ou
  `identite_invalide`) et de membre `detail` (texte ASCII, sans valeur
  secrète). Une erreur de programmation (paramètre d'un autre type) lève
  `TypeError`.
- Aléa : seulement `globalThis.crypto.getRandomValues`, présent sous Node 22
  et dans Chromium ; jamais `Math.random`.

### 0.5 Essais

Fichiers d'essai nommés `test/exploitation-console-*.test.js` : jamais
`test/console*.test.js`, préfixe réservé à la console de référence et exclu
de la lecture par les règles de salle blanche. Outils d'essai sous
`test/fixtures/exploitation-console/`. Un essai Chromium suit la règle
d'EX-13.36 : il est mis en attente, avec un message, si
`import("playwright")` échoue ou si Chromium ne se lance pas, et il échoue
quand `NOORTRACE_EXIGER_CHROMIUM` vaut `1` (version mesurée :
Playwright 1.56.1, installé sans être ajouté à `package.json`). Le matériel
TLS des essais est produit par `openssl` comme dans
`test/fixtures/ancrage-rfc3161/outils.mjs` (`certificatsTls`, `enAttente`),
et un essai qui en a besoin est mis en attente sans `openssl`. Les clés des
approbateurs d'essai sont dérivées du mnémonique public de CT-3 A.2 au
moment de l'essai ; aucune clé n'est écrite dans le dépôt.

## 1. Bibliothèque (`src/bibliotheque/`)

### 1.1 Contraintes d'exécution

La bibliothèque est faite de modules ECMAScript qui s'exécutent à
l'identique sous Node 22 et dans Chromium (EX-13.32) : ils n'importent que
des modules relatifs de `src/bibliotheque/`, `@noble/hashes/<fichier>.js` et
`@noble/curves/<fichier>.js` (spécificateurs nus, résolus sous Node par les
dépendances du paquet, et dans la page par la carte d'importation de 3.3) ;
ni `node:*`, ni `Buffer`, ni `process`, ni DOM (la découverte reçoit sa cible
d'événements en paramètre) ; ni `eval`, ni `Function`, ni réseau, ni
horloge, ni état global mutable. Nombres entiers au-delà de 2^53 en
`BigInt`. Chaque module commence par un commentaire qui nomme les règles de
CT-3 qu'il tient.

### 1.2 Contrôle de forme

Les fonctions qui reçoivent une requête du canal (`verifierInscription`,
`appliquerOperation`, `controleCanal`) contrôlent elles-mêmes sa forme,
exactement celle du `$defs` que nomme la table d'EX-12.13 (membres requis et
admis, types, motifs, longueurs) : la bibliothèque n'embarque pas de
validateur JSON Schema. Un essai sous Node confronte ce contrôle au
validateur du service (`RegistreSchemas`) sur chaque requête des vecteurs
et sur des variantes altérées (membre en trop, manquant, de mauvais type,
hors motif). `verifierAnnuaireExporte` reçoit au contraire le contrôle du
schéma de l'appelant (`conforme`), comme EX-13.32 le dit.

### 1.3 Module d'annuaire (`annuaire.mjs`, « @noortrace/console/annuaire »)

Une seule implémentation des règles de l'annuaire (CT-3 13.3 à 13.8) : celle
de ce module. Le service d'approbation l'importe et n'en garde aucune copie ;
la page l'emploie pour ses contrôles ; les vecteurs `annuaire/` le jugent.
Livré en premier, avant le reste de la bibliothèque.

| Export | Paramètres | Rend | Refus | Règles |
|---|---|---|---|---|
| `ErreurConsole` | `(code, detail?)` | classe d'erreur (0.4) | — | — |
| `analyserIdentite(texte)` | chaîne | `{ systeme: "oidc", iss, sub }` ou `{ systeme: "utilisateur", domaine, nom }` | lève `identite_invalide` | EX-13.7 |
| `identiteCanonique(champs)` | objet de la forme rendue par `analyserIdentite` | la chaîne canonique | lève `identite_invalide` | EX-13.7 |
| `estIdentiteCanonique(valeur)` | toute valeur | booléen | — | EX-13.7, EX-12.13 |
| `annuaireVide(reglages)` | `{ org, org_id, console_origin, registration_ttl_ms, administrators }` de la configuration du service | l'annuaire vide d'EX-13.38, point 1 : `version` 0, `revision` 0, `updated_at` nul, `entries` et `operations` vides | lève `identite_invalide` si `administrators` n'est pas de 1 à 64 identités canoniques distinctes | EX-13.38, EX-13.9 |
| `entreeDeSession(annuaire, identite)` | document, chaîne | l'entrée dont `session_identity` égale `identite`, ou `null` | — | EX-13.10 |
| `entreeActive(annuaire, identite)` | idem | l'entrée si elle est active, sinon `null` | — | EX-12.14 |
| `adresseActive(entree)` | entrée ou `null` | l'adresse `active` de l'entrée, ou `null` | — | EX-13.10, point 3 |
| `sessionDeLOrganisation(annuaire, identite)` | document, chaîne | vrai pour une identité de `administrators` ou d'une entrée active | — | EX-12.14 |
| `adressesConnues(annuaire)` | document | toutes les adresses de l'annuaire, tous états, triées, sans doublon | — | EX-8.1, pas 5 |
| `annuaireDeSession(annuaire, identite)` | document, chaîne | l'annuaire complet pour une identité de `administrators` ; sinon le document réduit à l'entrée de l'identité (0 ou 1) et aux opérations qui la visent, les autres membres gardés tels quels | — | EX-12.17 |
| `messageInscription(champs)` | `$defs/champs_inscription` | le texte exact de dix lignes | lève `message_invalide` (champ hors de sa grammaire) | EX-13.12 |
| `analyserMessageInscription(texte)` | chaîne | `$defs/champs_inscription` | lève `message_invalide` | EX-13.12 |
| `controleDefi(reponse, attendu)` | `$defs/reponse_preparer_inscription` ; `{ origine, identite, adresse }` (origine de la page, identité de la session, adresse choisie) | `null`, ou le premier de `message_invalide`, `origine_differente`, `identite_differente`, `adresse_differente`, dans cet ordre | — | EX-13.13 (côté console) |
| `verifierInscription(annuaire, defis, requete, recuA, options?)` | document ; tableau de `$defs/defi` ; corps d'`inscrire` ; instant de réception ; `{ identifiant: "aleatoire" \| "compteur" }`, défaut `aleatoire` | `{ accepted, reason, entry, signature, defis }` : `defis` est un nouveau tableau, état après le pas 4 d'EX-13.15 (défi présenté marqué `used`, quel que soit le sort) ; `entry` est l'entrée qui reçoit l'adresse, existante ou à créer, ou `null` ; `signature`, la forme normalisée gardée dans la preuve, ou `null` | dans `reason`, la première raison d'EX-13.15, pas 1 à 13 | EX-13.15, EX-9.3 |
| `appliquerOperation(annuaire, methode, requete, at, options?)` | document ; `preparer_inscription`, `inscrire`, `valider`, `revoquer`, `desactiver`, `reactiver`, `lier_demandeur` ou `delier_demandeur` ; corps de la méthode ; instant (horloge du service) ; `{ defis, nonce, identifiant }` (`defis` défaut `[]` ; `nonce` : celui que tire `preparer_inscription`, 32 chiffres hexadécimaux minuscules, tiré au hasard s'il est absent ; `identifiant` comme ci-dessus) | `{ annuaire, defis, accepted, reason, response }` : le nouvel annuaire (le même objet si refus), les défis après l'opération (défi ajouté ou remplacé ; défi présenté ; défis de l'identité effacés par `desactiver`), la réponse de la méthode (`$defs/reponse_preparer_inscription`, `reponse_adresse` ou `reponse_entree`) ou `null` | dans `reason`, la première raison de la méthode, forme et identité d'abord | EX-13.13, EX-13.15, EX-13.17, EX-13.10, EX-12.17 |
| `defisNonExpires(defis, at)` | tableau de `$defs/defi`, instant | les défis dont `expires_at` est postérieur à `at` | — | EX-13.38 (défis persistés) |
| `recopierAdministrateurs(annuaire, administrateurs, at)` | document, liste du réglage, instant | `{ annuaire, changed }` : l'opération `changer_administrateurs` (`by` `configuration`, `administrators` `{ before, after }`) si la liste diffère, comme liste, de la copie ; l'annuaire inchangé sinon | lève `identite_invalide` pour une liste hors de la forme d'EX-13.9 | EX-13.37 |
| `controleVote(annuaire, session, action, adresse, ticket)` | document ; identité de session ; `voter` ou `recuser` ; adresse choisie (comparée en minuscules) ; `{ launched_by, self_approval, policy_requester_addresses, directory_requester_addresses, members }` (forme du `ticket` de `$defs/fichier_controles_vote`, `members` nul avant le gel) | `{ allowed, reason, warnings }`, `warnings` portant `separation_incomplete` et ses adresses | dans `reason`, la première condition d'EX-13.18, conditions 1 à 6 (1 à 5 pour `recuser`) | EX-13.18 |
| `ticketDeControleVote(vue)` | `$defs/vue_ticket` | l'objet `ticket` de `controleVote`, tiré de la vue (`request.delegation.launched_by`, `separation`, `approver_set`) | — | EX-13.18, EX-12.15 |
| `actionRetrait(annuaire, session, ticket)` | document ; identité ; `{ launched_by }` | le `by` d'un retrait que la console peut envoyer, ou `null` | — | EX-13.18, EX-7.15 |
| `controleCanal(annuaire, methode, requete, ticket)` | document ; `tickets`, `consulter`, `voter`, `recuser` ou `retirer` ; corps ; `{ launched_by, eligible }` ou `null` (ticket inconnu dans l'organisation, et toujours pour `tickets`) | `null`, ou `identite_invalide`, `session_non_autorisee`, `ticket_inconnu` | la première, dans l'ordre d'EX-12.14 et d'EX-12.19 | EX-12.13, EX-12.14, EX-12.16, EX-12.19 |
| `verifierAnnuaireExporte(document, options?)` | document ; `{ conforme }`, fonction `(document) → booléen`, contrôle du schéma `annuaire-approbateurs-v0` par l'appelant | la liste complète des écarts `{ code, pointer }`, triée par pointeur puis par code (unités UTF-16) ; `[{ "code": "schema", "pointer": null }]` pour un document non conforme | — | EX-13.19, EX-13.37 |

Précisions :

- **Identifiant d'une entrée créée.** `compteur` : `apb-` et, sur quatre
  chiffres décimaux complétés de zéros, le nombre d'entrées avant la création
  plus un (convention des vecteurs, A.10) ; `aleatoire` : `apb-` et 16
  chiffres hexadécimaux minuscules de 64 bits tirés au hasard (EX-13.9,
  EX-13.38), tiré de nouveau en cas de collision avec une entrée existante.
  `appliquerOperation(…, "inscrire", …)` applique le rendu de
  `verifierInscription` sur la même requête, au même instant : même sort,
  même raison, même `entry`, même signature normalisée.
- **`tickets` avec `related_to`.** `controleCanal(annuaire, "tickets", …)`
  n'applique que le point 1 d'EX-12.14 ; pour `related_to`, le service
  appelle en plus `controleCanal(annuaire, "consulter", { ticket:
  related_to, session_identity }, info)` (EX-12.21).
- **Pureté.** Aucune fonction ne modifie ses paramètres ; les rendus sont
  des objets neufs, sérialisables par `JSON.stringify`.

**Ce qui existe déjà dans `paquets/approbation/src/annuaire.mjs`, et ce
qu'il devient.** Ce module de l'étape 4 exporte `identiteCanonique(s)` (un
**prédicat** booléen, de même nom que la fonction d'EX-13.32 mais d'un autre
sens), la classe `Annuaire` (lecture : `lire`, `vide`, `entree`,
`entreeActive`, `adresseActive`, `sessionDeLOrganisation`, `adresses`,
`administrators`) et `controleCanal(annuaire, …)`, qui reçoit une instance
d'`Annuaire`. À l'étape 6, le service supprime ces trois implémentations et
importe celles de ce module : `estIdentiteCanonique` remplace le prédicat ;
`entreeActive`, `adresseActive`, `sessionDeLOrganisation`, `adressesConnues`
et `controleCanal` remplacent les méthodes de la classe et sa fonction ;
`annuaireVide` remplace `Annuaire.vide`, dont l'organisation `organisation`,
l'origine `https://console.invalid` et l'`updated_at` non nul contredisent
EX-13.38. Le service garde un objet d'état à lui (document courant, défis,
persistance), qui ne réécrit aucune règle. `@noortrace/approbation` peut
réexporter les fonctions de ce module ; il n'exporte plus de prédicat nommé
`identiteCanonique`.

### 1.4 Signatures et portefeuille

| Export | Paramètres | Rend | Règles |
|---|---|---|---|
| `donneesPersonalSign(texteOuOctets)` | chaîne ou `Uint8Array` | `"0x"` et l'hexadécimal minuscule des octets UTF-8 du texte, ou des octets | EX-13.12, EX-13.16 |
| `requetePersonalSign(donnees, adresse)` | `"0x…"` (`D_A`, 66 caractères, ou rendu de `donneesPersonalSign`) ; adresse | `{ method: "personal_sign", params: [donnees, adresse en minuscules] }`, données d'abord | EX-13.24, EX-13.16 |
| `preimageEip191(octets)`, `condenseEip191(octets)` | `Uint8Array` | la préimage `0x19 ‖ "Ethereum Signed Message:\n" ‖ décimal(L) ‖ octets` ; son Keccak-256 (`"0x…"`) | EX-13.12, 13.9 pas 5 |
| `verifierSignature(octets, signature, adresse)` | octets signés (32 octets de `D_A`, ou octets du texte) ; signature telle que reçue ; adresse attendue | `{ valide, reason, signature, recovered }` : `signature` normalisée (EX-9.3 : 65 octets, `v` ramené à 27 ou 28, `s` bas) ou `null`, `recovered` ou `null` si la forme est refusée avant le recouvrement, `reason` nul, `signature_invalide` ou `adresse_differente` ; la forme est contrôlée avant toute primitive (EX-9.22) | EX-9.3, EX-9.21, EX-9.22 |
| `codeErreurPortefeuille(erreur)` | erreur EIP-1193 rompue (`{ code, message }`, `code` nul sans code numérique) | `refus_approbateur` (4001), `non_autorise` (4100), `methode_non_prise_en_charge` (4200), `deconnecte` (4900), `chaine_deconnectee` (4901), `erreur_portefeuille` (tout autre cas) | EX-13.29 |
| `verifierReponse(reponse, octets, adresse)` | `$defs/reponse_portefeuille` (`{ result }` ou `{ error }`) ; octets signés ; adresse choisie | `{ outcome, reason, signature, recovered }` (les membres de même nom d'`expected` de `$defs/cas_reponse`) : promesse rompue, code de `codeErreurPortefeuille` ; tenue avec autre chose qu'une chaîne `0x` hexadécimale, `reponse_invalide` ; sinon `verifierSignature` | EX-9.21, EX-13.29 |
| `analyserComptes(resultat)` | résultat d'`eth_requestAccounts` | les adresses en minuscules, ou `null` (`reponse_invalide`) | EX-13.23 |
| `echeanceAttente(delaiSignatureMs, deadline, maintenant)` | entier ; instant ou `null` ; instant | l'attente admise en millisecondes, `min(delai, deadline − maintenant)` (le délai seul sans échéance) ; `≤ 0` : `delai_depasse` | EX-13.30 |

### 1.5 Vue, condensés, modèle d'affichage, découverte

| Export | Paramètres | Rend | Règles |
|---|---|---|---|
| `analyserJsonStrict(entree)` | chaîne ou `Uint8Array` UTF-8 | la valeur ; lève `ErreurConsole` (`code` `piece_invalide`) sur clé en double, substitut isolé, UTF-8 invalide | EX-9.6, CT-1 §4 |
| `jcs(valeur)` | valeur JSON | la forme canonique JCS v0 (chaîne) | CT-1 §4 |
| `hachageEvenement(evenement)` | événement CT-1 | `"0x…"` (CT-1 §6.1) | EX-9.15 (2) |
| `condenses(a)` | objet `A` (`$defs/condenses/properties/a`) | `$defs/condenses` : `a`, `jcs`, `d_a`, `fingerprint`, `groups`, `h`, `h_fingerprint`, `utf8` | EX-9.17 à EX-9.19 |
| `empreinte(x)`, `groupes(x)` | `"0x"` et 64 chiffres | 8 chiffres, U+2026, 8 chiffres ; 8 groupes de 8 séparés par une espace | EX-9.18 |
| `modeleAffichage(vue, contexte)` | `$defs/vue_ticket` ; `{ session: { session_identity, entry, addresses, is_requester }, decision, approver, reason, now }` (l'`input` de `$defs/cas_modele` sans `view`) | `$defs/modele_affichage`, `blocking` complet et ordonné selon EX-9.15 et ses sauts | EX-9.4, EX-9.6, EX-9.15 à EX-9.19, EX-12.14 |
| `sessionDuModele(annuaire, identite, vue)` | document ; identité ; vue | l'objet `session` du contexte : `entry` `absente`, `active` ou `desactivee`, `addresses` l'adresse active (ou vide), `is_requester` | EX-9.15 (9, 12) |
| `requeteVoter(vue, decision, signature, adresse, motif, session)` | vue du ticket signé ; décision ; signature normalisée ; adresse ; motif ou `null` ; identité de session | le corps exact de `voter` (`$defs/requete_voter`) | EX-9.21, EX-12.16 |
| `decouvrir(annonces)` | tableau d'`{ info, provider }` dans l'ordre d'arrivée (`provider` comparé par identité, `===`) | `{ providers, rejected }` de `$defs/cas_decouverte`, chaque fournisseur avec `uuid`, `name`, `icon`, `rdns`, `provider` | EX-13.22, points 2 et 3 |
| `Decouverte` | `new Decouverte(cible)`, `cible` un `EventTarget` (`window` dans la page) | `lancer()` pose l'écouteur de `eip6963:announceProvider` puis émet `eip6963:requestProvider` ; `fournisseurs` (liste courante, ordre des premières annonces, aucun choix) ; `ecartees` ; `surChangement(fonction)` ; aucun minuteur (le délai de 1 000 ms est celui de la page) ; l'écouteur n'est jamais retiré | EX-13.22 |
| `METHODES_CANAL` | — | les quatorze méthodes de la table d'EX-12.13 (`tickets`, `consulter`, `voter`, `recuser`, `retirer`, `annuaire`, `preparer_inscription`, `inscrire`, `valider`, `revoquer`, `desactiver`, `reactiver`, `lier_demandeur`, `delier_demandeur`) | EX-12.13 |
| `METHODES_REAUTHENTIFICATION` | — | les onze méthodes de la liste d'EX-13.8 | EX-13.8 |
| `CODES_CONSOLE` | — | l'énumération `$defs/code_console`, figée | 13.14 |

La bibliothèque PEUT exporter d'autres fonctions (primitives, aides) : elle
les nomme dans son `LISEZMOI.md` ; aucune autre partie n'en dépend sans que
ce contrat les nomme.

### 1.6 Ce que la bibliothèque n'offre pas

`lireFichierCle` et `signerCondense` (parcours d, EX-13.28) ne sont pas
exportés : le parcours d n'est pas offert. Rien n'est écrit pour le
parcours c (WalletConnect). Les cas `console/fichiers-cle/` des vecteurs sont
inventoriés et mis en attente par les essais, avec cette raison.

### 1.7 Essais de la bibliothèque

- Sous Node : chaque cas des familles `annuaire/` (`messages.json`,
  `inscriptions.json`, `domaines.json`, `traces/*.json`,
  `controles-vote.json`, `controles-canal.json`, `exports/`) et `console/`
  (`modeles/`, `requetes/`, `reponses/`, `decouverte/`) rejoué contre son
  `expected`, sans écart ; le contrôle de forme de 1.2 confronté au
  validateur du service ; essai différentiel des primitives (Keccak-256,
  SHA-256, JCS, recouvrement EIP-191) contre `@noortrace/noyau` et ethers ;
  pureté (aucun import interdit par 1.1, vérifié sur le texte des modules).
- Dans Chromium : la même suite de cas, chargée sous la politique
  d'EX-13.35 et sous la carte d'importation de la bibliothèque, rend les
  mêmes résultats, octet pour octet sur leur JSON.

## 2. Serveur de console (`src/serveur/`, `bin/noortrace-console`)

### 2.1 Ligne de commande

```text
noortrace-console --config <fichier>                  sert la console (EX-10.13)
noortrace-console valider-configuration <fichier>     rapport d'EX-10.13, codes 0, 1, 2
noortrace-console sonde [--config <fichier>]          sonde d'EX-13.44 (défaut /etc/noortrace-console/configuration.json), codes 0 et 1
noortrace-console --version                           nom et version du paquet
```

`--config` se donne comme argument distinct (`--config <fichier>`). Au
démarrage, le serveur valide la configuration (mêmes règles que
`valider-configuration` ; refus : code 1 et le rapport sur la sortie
d'erreur, avant toute écoute), résout ses références, vérifie le manifeste
des pages (2.12), lit la découverte OIDC (EX-13.45, point 1, sans en faire
dépendre le démarrage), puis écoute et écrit sur la sortie standard une
ligne `{"pret":true,"pid":<n>,"ecoute":{"host":<h>,"port":<p>}}`. SIGTERM et
SIGINT l'arrêtent proprement. Usage incorrect : code 2.

### 2.2 Interface programmatique (`@noortrace/console/serveur`)

```js
import { demarrerServeur, validerConfiguration, sonder, principal } from "@noortrace/console/serveur";

const r = validerConfiguration(octets);          // { valide, errors } (EX-10.13), sans lire de secret
const srv = await demarrerServeur({
  config,                // document validé (configuration-console-v0)
  base,                  // répertoire du fichier de configuration (références relatives)
  horloge,               // facultatif : () => millisecondes depuis l'époque (essais)
  agentHttps,            // facultatif : https.Agent pour joindre le fournisseur OIDC et le service (essais)
  pages,                 // facultatif : répertoire qui porte manifeste.json et ecrans/ (essais ; défaut src/pages/)
});
srv.adresse              // { host, port } réellement écoutés
await srv.arreter();
const s = await sonder({ chemin });              // { code: 0|1, sortie, erreur } (EX-13.44)
await principal(argv);   // ligne de commande ; rend le code de sortie
```

### 2.3 Configuration

Document `configuration-console-v0`, analysé en JSON strict
(`lireJsonStrict` du service), validé contre les copies embarquées sous
`schemas/` : `configuration-console-v0`, `configuration-approbation-v0`,
`annuaire-approbateurs-v0`, `evenement-v0`, `ticket-v0` et
`console-service-v0`, enregistrées dans un `RegistreSchemas` du service ; un
essai compare chaque copie à `spec/schemas` octet pour octet. Puis les règles
d'EX-10.13 (`identite_locale_en_production`, `tls_exige`,
`authentification_exigee`, `certificat_client_incomplet`). Rapport
`$defs/rapport_validation` : `{ "valide", "errors" }`, erreurs `{ "code",
"pointer" }`, `json` (seule erreur, pointeur vide) pour un fichier illisible
ou hors JSON strict, une erreur `schema` au pointeur de chaque membre fautif
(les règles ne sont alors pas évaluées), tri par pointeur puis par code
(unités UTF-16). Défauts des membres facultatifs : ceux des descriptions du
schéma (`reauth_max_age_s` 900, `service_timeout_ms` 10 000,
`delai_signature_ms` 300 000, `session_max_age_s` 28 800,
`id_token_signing_alg_values` `["RS256"]`, `cache_s` 3 600, `walletconnect`
nul). Un `walletconnect` non nul est accepté par la validation mais le
serveur refuse de démarrer avec lui (code 1, « parcours c non offert par
cette console ») : le parcours c n'est pas offert.

Références de secret (`{ "file" }` relatif au répertoire du fichier de
configuration, ou `{ "env" }`) : certificat et clé TLS en PEM, le certificat
du serveur en tête de la chaîne ; `service.token` de 16 à 1 024 caractères
ASCII imprimables, espaces de tête et de fin retirés ; `service.ca`,
`service.client_cert`, `service.client_key` en PEM ; `identity.client_secret`
(octets lus, espaces de tête et de fin retirés) ; `identity.accounts`
conforme à `$defs/fichier_comptes`, noms deux à deux distincts. Une
référence illisible ou mal formée arrête le démarrage (code 1), en nommant le
pointeur, jamais la valeur.

### 2.4 Adresses servies

Toutes sous `console_origin`, chemins comparés octet pour octet, sans barre
finale (EX-13.43). `HEAD` est admis partout où `GET` l'est.

| Méthode | Chemin | Session | Corps de requête | Réponse | Erreurs propres |
|---|---|---|---|---|---|
| `GET` | `/` | non | — | 303, `Location: /tickets` | — |
| `GET` | `/tickets` | non | — | 200, `ecrans/tickets.html` | — |
| `GET` | `/tickets/<ticket>` | non | — | 200, `ecrans/ticket.html` ; `<ticket>` au motif `^apr-[0-9a-z]+(-[0-9a-z]+)*$`, de 5 à 128 caractères | 404 si le segment est hors du motif |
| `GET` | `/inscription` | non | — | 200, `ecrans/inscription.html` | — |
| `GET` | `/annuaire` | non | — | 200, `ecrans/annuaire.html` | — |
| `GET` | `/connexion` | non | paramètre facultatif `retour` | OIDC : 303 vers `authorization_endpoint` et cookie de transaction (EX-13.45, point 2) ; local : 200, `ecrans/connexion.html` (EX-13.47) | OIDC : page d'erreur (2.6) `fournisseur_indisponible` (502) ou `fournisseur_erreur` (400) |
| `GET` | `/connexion/retour` | cookie de transaction | paramètres `code`, `state`, `iss` ou `error` | 303 vers `retour`, cookie de session posé, cookie de transaction effacé (EX-13.45, point 5) | page d'erreur : `transaction_inconnue`, `fournisseur_erreur`, `jeton_invalide`, `identite_invalide` (400), `fournisseur_indisponible` (502) ; local : 404 |
| `POST` | `/connexion/locale` | non | `$defs/requete_connexion_locale` | 204 et cookie de session | 401 `identifiants_refuses` ; 429 `essai_trop_tot` (`data.retry_after_s`, et en-tête `Retry-After`) ; OIDC : 404 `requete_invalide` |
| `POST` | `/deconnexion` | non (sans effet sans session) | vide, ou `{}` | 204, les deux cookies effacés (EX-13.48, point 6) | — |
| `POST` | `/v0/session` | oui | `{}` (`$defs/requete_session`) | 200, `$defs/reponse_session` | 401 `session_absente` |
| `POST` | `/v0/<méthode>` | oui | requête de la méthode (12.9), `session_identity` imposée (2.10) | statut et corps du service, tels quels (2.10) | 401 `session_absente`, 401 `reauthentification_requise` (`data.reauth_max_age_s`), 504 `service_indisponible`, 404 `requete_invalide` (méthode hors de la table d'EX-12.13) |
| `GET` | `/v0/sante` | non | — | 200, `$defs/reponse_sante` (EX-13.44) | — |
| `GET` | `/statique/<chemin>` | non | — | 200, le fichier du manifeste (2.12) | 404 si le chemin n'est pas au manifeste |

Méthode HTTP non admise pour un chemin de la table ou un fichier du
manifeste : 405, `requete_invalide`, en-tête `Allow` (`GET, HEAD` ou `POST`).
Tout autre chemin : 404, `requete_invalide`.

### 2.5 Ordre de traitement

Chaque requête passe, dans cet ordre, la première condition remplie
donnant la réponse :

1. en-tête `Host` différent, en minuscules, de l'autorité de
   `console_origin` (hôte, et port s'il y figure) : 421 `hote_refuse` ;
2. méthode autre que `GET` et `HEAD`, et en-tête `Origin` absent ou
   différent, octet pour octet, de `console_origin` : 403 `origine_refusee` ;
3. requête qui annonce un corps (`Content-Length` non nul ou
   `Transfer-Encoding`) dont le type de média n'est pas `application/json`
   (casse ignorée, paramètres ignorés) : 400 `requete_invalide` ;
4. chemin inconnu : 404 ; méthode HTTP non admise : 405 (2.4) ;
5. corps de plus de 65 536 octets (lu jusqu'à 65 537 octets au plus) : 413
   `requete_invalide`, sans relais ;
6. corps qui n'est pas du JSON strict, ou que `$defs/requete_session`
   (`/v0/session`) ou `$defs/requete_connexion_locale` (`/connexion/locale`)
   refuse, ou corps relayé qui n'est pas un objet : 400 `requete_invalide` ;
7. traitement de la route (session, réauthentification, relais).

Aucune réponse ne porte d'en-tête `Access-Control-Allow-*` ni de
`Set-Cookie` autre que les deux cookies d'EX-13.48.

### 2.6 En-têtes et formes de réponse

Chaque réponse du serveur porte :

| En-tête | Valeur |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self' '<carte_sha256>'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'`, exactement, `<carte_sha256>` étant celui du manifeste (`sha256-` et le base64 du SHA-256 de la carte) |
| `Integrity-Policy` | `blocked-destinations=(script)` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Strict-Transport-Security` | `max-age=31536000` |
| `Cache-Control` | `no-cache` sous `/statique/` ; `no-store` partout ailleurs |

Les deux premiers sont exigés par EX-13.35 sur toute réponse HTML ; les
autres sont un choix de l'étape 6, posé sur toute réponse pour qu'une seule
règle s'éprouve. `Content-Type` : `text/html; charset=utf-8`,
`text/css; charset=utf-8`, `text/javascript; charset=utf-8`,
`application/json; charset=utf-8`.

Une erreur que le serveur rend lui-même a la forme `$defs/erreur` de
`console-service-v0`, `code` dans `$defs/code_serveur_console`, `message`
ASCII, sauf sur les navigations `GET /connexion` et `GET
/connexion/retour`, où elle est une **page d'erreur** HTML produite par le
serveur, sans script, sous les mêmes en-têtes : un titre, le code en texte
(échappé), la valeur d'`error` du fournisseur le cas échéant (en texte), et
un lien vers `/connexion` (EX-13.49, dernier paragraphe).

### 2.7 Sessions et cookies

Exactement EX-13.48 : sessions en mémoire (au plus 10 000, la plus ancienne
détruite au-delà), `sid` de 32 octets, échéance `session_max_age_s` depuis
la création, sans délai d'inactivité ; cookie `__Host-noortrace-session`
(`Secure; HttpOnly; SameSite=Strict; Path=/`, valeur
`base64url(sid) "." base64url(HMAC-SHA256(K_s, "noortrace/console/session/v0\n" ‖ sid))`,
MAC vérifié en temps constant avant la recherche) ; cookie
`__Host-noortrace-connexion` (`Secure; HttpOnly; SameSite=Lax; Path=/;
Max-Age=600`, AES-256-GCM sous `K_t`, données associées
`noortrace/console/connexion/v0`) ; `K_s` et `K_t` tirées au démarrage,
distinctes, jamais écrites. Une session garde : identité, `auth_time`
(instant d'authentification), création, échéance, `administrator`, et, pour
`reauth_max_age_s` = 0, le fait qu'une méthode de la liste d'EX-13.8 a déjà
été relayée sur cette authentification. Le rôle `administrator` est celui du
dernier annuaire que le service a rendu pour la session : le serveur relaie
`annuaire` à la création de la session (faute de réponse, `false`) et met le
rôle à jour à chaque réponse `annuaire` relayée.

### 2.8 OIDC

Exactement EX-13.45 et EX-13.46 : découverte et jeu de clés relus d'avance à
la moitié de `cache_s`, relecture retentée toutes les 60 s, copie gardée
jusqu'à `cache_s` ; demande par code avec PKCE `S256`, `scope=openid`,
`max_age=<reauth_max_age_s>` toujours, `prompt=login` pour 0 ;
`redirect_uri` `<console_origin>/connexion/retour` ; transaction portée
entière par le cookie chiffré ; `tid` consommé à la première présentation
(au plus 100 000 gardés 600 s) ; échange par `client_secret_basic` ; jeton
vérifié par le serveur, jamais par la page, dans l'ordre des neuf points
d'EX-13.46, tolérance d'horloge 60 s. Lectures et échanges : 10 000 ms au
plus, 1 048 576 octets au plus, aucune redirection suivie, certificat du
fournisseur vérifié contre le magasin du système (la configuration n'a pas
d'autorité propre au fournisseur ; les essais passent la leur par
`agentHttps` ou `NODE_EXTRA_CA_CERTS`).

### 2.9 Système local (hors production)

Exactement EX-13.47 : identité `utilisateur <identity.domain> <name>` ;
scrypt (N = 131 072, r = 8, p = 1, 32 octets ; `maxmem` d'au moins 128 Mio
plus une marge) comparé en temps constant ; même calcul sur un sel fixe pour
un nom inconnu ; deux calculs à la fois au plus (le troisième : 429
`essai_trop_tot`, `retry_after_s` 1) ; verrou progressif par nom
(`min(2^(f − 5), 900)` s dès `f ≥ 5`, 10 000 noms suivis, éviction d'abord
des noms non verrouillés). `auth_time` est l'instant de la vérification.
`environment` `production` avec ce système : refus de démarrer
(`identite_locale_en_production`).

### 2.10 Relais vers le service

Le serveur est le seul client du canal de la console (CT-3 12.9, EX-12.4) :

- base : `service.url`, ou `http://localhost` sur la prise `service.socket` ;
  requête `POST <base>/v0/<méthode>`, `Content-Type: application/json`,
  `Authorization: Bearer <service.token>` si le jeton est déclaré, certificat
  client si `service.client_cert` l'est, certificat du service vérifié contre
  `service.ca` (sinon le magasin du système) ;
- méthodes relayées : exactement les quatorze de la table d'EX-12.13
  (`METHODES_CANAL` de la bibliothèque) ; `session` n'est jamais relayée ;
- **imposition** : le corps reçu de la page, objet JSON strict, est relayé
  avec `session_identity` posée à l'identité de la session, ajoutée si elle
  manque, remplacée sinon (13.18) ; aucun autre membre n'est changé ni
  contrôlé : le service contrôle la forme (EX-12.13) ;
- **réauthentification** : avant une méthode de `METHODES_REAUTHENTIFICATION`,
  `auth_time` doit dater de moins de `reauth_max_age_s` secondes ; avec 0,
  l'authentification ne vaut que pour la première méthode de la liste relayée
  dans les 600 s qui la suivent ; sinon 401 `reauthentification_requise`,
  `data.reauth_max_age_s`, sans relais (EX-13.48, point 5) ;
- **délai** : `service_timeout_ms` (défaut 10 000) depuis l'envoi jusqu'à la
  fin du corps de la réponse ; au-delà, ou service injoignable, ou réponse de
  plus de 16 777 216 octets (`body_max_bytes` par défaut du service), 504
  `service_indisponible` ;
- **réponse** : statut et corps du service rendus tels quels, avec
  `Content-Type: application/json; charset=utf-8` et les en-têtes de 2.6 ;
- **rôle** : sur une réponse 200 d'`annuaire`, `administrator` de la session
  devient « l'identité figure dans `administrators` du document rendu ».

### 2.11 Santé et sonde

Exactement EX-13.44 : `GET /v0/sante` sans session ; `service_reachable` par
`GET <base>/v0/etat` sur le canal de la console, avec ses identifiants, 200
et corps de la forme d'EX-12.12 dans les 1 000 ms, résultat gardé 5 s ;
`identity_ready` (OIDC : découverte et clés lues depuis moins de `cache_s` ;
local : fichier des comptes chargé) ; `ready` ; `checked_at`. La sonde ne lit
de la configuration que `console_origin`, `listen` et `tls.cert`, joint
`listen.host` (`127.0.0.1` pour `0.0.0.0`, `::1` pour `::`) avec la SNI de
l'hôte de `console_origin`, exige le premier certificat de `tls.cert` (SHA-256
du DER), envoie `GET /v0/sante` avec `Host` égal à l'autorité de
`console_origin`, attend 2 500 ms au plus, écrit le corps sur une ligne
(sortie standard) ou la raison (sortie d'erreur) ; codes 0 et 1 seulement.

### 2.12 Fichiers servis et manifeste

Le serveur ne sert que ce que nomme `src/pages/manifeste.json` (3.3) : les
cinq écrans et les fichiers sous `/statique/`. Au démarrage, il lit chaque
fichier, en recalcule le SHA-384 et le SHA-256, et refuse de démarrer (code
1) sur un écart avec le manifeste ; il sert ensuite les octets lus au
démarrage, jamais relus. La source d'un fichier de `@noble/*` est résolue
depuis `src/serveur/` : racine du paquet = répertoire de
`import.meta.resolve("<paquet>/utils.js")` (les deux paquets exportent
`./utils.js` à leur racine ; leurs fichiers internes, comme `_u64.js`, ne
sont pas des sous-chemins exportés). `<carte_sha256>` de la CSP est celui du
manifeste.

### 2.13 Journal du serveur

Une ligne JSON par événement sur la sortie d'erreur : `{ "ts", "event",
"data" }`. Événements : `serveur_pret`, `serveur_arrete`,
`decouverte_oidc` (`ok`, `cause`), `session_ouverte` (`session_identity`,
`auth_time`, `systeme`), `session_fermee` (`cause` : `deconnexion`,
`remplacee`, `echeance`, `eviction`), `connexion_refusee` (`code`),
`reauthentification_requise` (`methode`, `auth_time`), `relais` (`methode`,
`statut`, `duree_ms`, `session_identity`, `auth_time`). Jamais un jeton, un
secret, une valeur de cookie, un mot de passe, un code d'autorisation ni un
corps de requête ou de réponse. `auth_time` est gardé ici et nulle part
ailleurs (EX-13.8).

### 2.14 Essais du serveur

Fournisseur OIDC simulé dans le dépôt
(`test/fixtures/exploitation-console/fournisseur-oidc.mjs`) : HTTPS local,
découverte, jeu de clés (RSA 2 048 bits et EC P-256 tirés au lancement),
point d'autorisation qui rend un code sans interaction, point de jeton qui
exige `client_secret_basic` et le `code_verifier`, et un réglage par défaut
pour chaque point d'EX-13.45 et d'EX-13.46 (document fautif, `kid` absent,
`alg` refusé, `aud` multiple, `nonce`, `auth_time`, `iat`, `exp`, `sub`
non canonique…). Service simulé (`test/fixtures/exploitation-console/service.mjs`) :
canal de la console avec jeton, réponses et délais réglables, `GET /v0/etat`.
Oracles : TE-20, TI-22, TA-100 (voir l'étape 6 du plan de tests), plus
l'ordre de 2.5, les en-têtes de 2.6 sur chaque réponse, l'imposition de
`session_identity`, la réauthentification pour chacune des onze méthodes.

## 3. Pages (`src/pages/`)

### 3.1 Écrans

| Adresse | Fichier | Écran |
|---|---|---|
| `/tickets` | `ecrans/tickets.html` | liste des tickets (EX-13.3, EX-12.21) |
| `/tickets/<ticket>` | `ecrans/ticket.html` | un ticket : modèle d'EX-9.4, signature, objection, récusation, retrait ; tickets refusés ou expirés du même demandeur et du même outil |
| `/inscription` | `ecrans/inscription.html` | « Mon adresse » : état de son entrée, inscription par preuve de possession (13.5) |
| `/annuaire` | `ecrans/annuaire.html` | annuaire, pour les administrateurs (13.6) : valider, révoquer, désactiver, réactiver, lier et délier un alias de demandeur, exporter |
| `/connexion` (système local) | `ecrans/connexion.html` | connexion par nom et mot de passe (EX-13.47) |

Les écrans sont statiques et ne portent aucune donnée (EX-13.43). Au
chargement, le module de l'écran pose d'abord la découverte EIP-6963
(`new Decouverte(window).lancer()`, sur les écrans Ticket et Mon adresse),
puis appelle `POST /v0/session` : sur 401 `session_absente`, il navigue vers
`/connexion?retour=<chemin de l'écran>` (encodé par
`encodeURIComponent`) ; une identité que `analyserIdentite` refuse donne le
seul affichage de `identite_invalide` (EX-13.7), sans autre lecture.

### 3.2 Fichiers et chemins

- `/statique/console.css` : la feuille de style ; polices du système ;
  thème clair et sombre par `prefers-color-scheme` seulement (aucun script,
  aucun stockage) ; aucune couleur, aucun logo ni nom de marque.
- `/statique/ecrans/<écran>.mjs` : module d'entrée de chaque écran.
- `/statique/commun/*.mjs` : client de `/v0/` (`fetch` de même origine,
  `credentials: "same-origin"`, `Content-Type: application/json`),
  construction du DOM par `createElement` et `textContent`, libellés.
- `/statique/libelles/fr.mjs` : les textes (3.6).
- `/statique/bibliotheque/<module>.mjs` : les modules de `src/bibliotheque/`.
- `/statique/modules/@noble/hashes/<fichier>.js`,
  `/statique/modules/@noble/curves/<fichier>.js` : les fichiers de ces
  paquets que la bibliothèque importe, directement ou non.

### 3.3 Carte d'importation, intégrité, manifeste

Chaque écran porte, dans son `<head>`, dans cet ordre : `<meta charset>`,
`<meta name="viewport">`, `<title>`, `<link rel="stylesheet"
href="/statique/console.css" integrity="sha384-…">`, la carte
d'importation `<script type="importmap">…</script>` (seul script en ligne),
puis `<script type="module" src="/statique/ecrans/<écran>.mjs"
integrity="sha384-…"></script>`. La carte est **la même** dans les cinq
écrans (un seul condensé dans `script-src`) :

```json
{"imports":{"noortrace-console/":"/statique/bibliotheque/","@noble/hashes/":"/statique/modules/@noble/hashes/","@noble/curves/":"/statique/modules/@noble/curves/"},"integrity":{"/statique/…":"sha384-…"}}
```

`integrity` nomme **chaque** module JavaScript servi sous `/statique/`
(entrées, modules communs, libellés, bibliothèque, `@noble/*`), en chemins
absolus de l'origine, triés ; la carte est écrite par `JSON.stringify` sans
espace. Un module chargé sans intégrité dans la carte est bloqué par
`Integrity-Policy` : la page ne s'initialiserait pas.

`src/pages/construire.mjs` produit, de façon déterministe (aucune date,
aucun aléa, aucun chemin de la machine), les cinq écrans et
`src/pages/manifeste.json` ; `node src/pages/construire.mjs` vérifie
(code 1 si un fichier produit est périmé), `--ecrire` réécrit ; un essai
exige qu'ils soient à jour. La liste des fichiers `@noble/*` est la
fermeture des importations statiques depuis la bibliothèque. Forme du
manifeste (interne au paquet) :

```json
{
  "version": 0,
  "carte": "<texte exact de la carte d'importation>",
  "carte_sha256": "sha256-<base64>",
  "ecrans": {
    "tickets": { "fichier": "ecrans/tickets.html", "sha384": "sha384-<base64>", "sha256": "0x<64>" },
    "ticket": { … }, "inscription": { … }, "annuaire": { … }, "connexion": { … }
  },
  "statiques": [
    {
      "chemin": "/statique/console.css",
      "source": { "paquet": "@noortrace/console", "fichier": "src/pages/statique/console.css" },
      "type": "text/css; charset=utf-8",
      "sha384": "sha384-<base64>",
      "sha256": "0x<64>",
      "octets": 0
    }
  ]
}
```

`statiques` est trié par `chemin` ; `source.paquet` vaut `@noortrace/console`,
`@noble/hashes` ou `@noble/curves`, `source.fichier` étant relatif à la
racine du paquet. Les SHA-256 du manifeste sont les empreintes à publier
(CT-8 EX-3.14).

### 3.4 Comportement des écrans

Toutes les lectures et actions passent par `POST /v0/<méthode>` (13.9,
13.18) ; la page met dans chaque corps la `session_identity` lue par
`session`. Une erreur `reauthentification_requise` fait naviguer vers
`/connexion?retour=<écran>` ; `session_absente`, de même ;
`service_indisponible`, ou une erreur du service, s'affiche avec son code
(13.14).

- **Tickets.** `tickets` (sans `related_to`) ; pour chaque ticket :
  identifiant (lien `/tickets/<ticket>`), outil annoncé, demandeur,
  échéance, votes `approuve` et `refuse` sur `effective_required`, état de
  la fenêtre de contestation (`contest_ms`, `contest`) ; nombre de tickets
  ouverts par demandeur (EX-14.2).
- **Ticket et signature** (parcours a et b, 13.9 à 13.11) : pas 1,
  `consulter`, `annuaire` et `tickets` avec `related_to` ; affichage du modèle
  (`modeleAffichage`) avec chaque marque, l'empreinte de chaque décision et
  les consignes d'EX-9.20 (dont l'origine `console_origin` de la console
  saine, lue dans l'annuaire) ; « Approuver » et « Refuser » chacun en un
  clic puis une confirmation, sans présélection (EX-9.5), l'avertissement
  sur le motif (EX-13.6) ; choix explicite du fournisseur (liste de
  `Decouverte`, icône par `<img>` seulement, `rdns` « déclaré par le
  portefeuille, non vérifié », « aucun portefeuille ne s'est annoncé »
  1 000 ms après `lancer()` si la liste est vide) ; `eth_requestAccounts`,
  `analyserComptes`, adresse active retenue (EX-13.23) ; pas 3, nouvelles
  lectures, `modeleAffichage` et `controleVote` : `personal_sign` seulement
  si `blocking` est vide, sur l'action explicite de l'écran qui affiche
  l'empreinte (EX-13.21), une requête à la fois, attente bornée par
  `echeanceAttente` avec le `delai_signature_ms` de `session` ; avant de
  demander la signature, la page vérifie par `session` que la
  réauthentification ne sera pas exigée avant l'envoi du vote (règle de
  3.5), et fait réauthentifier d'abord sinon ; pas 6 et 7, `verifierReponse`,
  puis nouvelles lectures, et `controleVote` de nouveau si `state` ou
  `revision` ont changé ; pas 8, `voter` avec `requeteVoter` ; `vote_identique`
  affiché « vote déjà inscrit » (EX-12.16) ; un autre ticket ouvert, un
  changement de décision ou d'adresse, ou `accountsChanged` qui retire
  l'adresse, abandonne l'écran de signature et ignore toute réponse tardive.
  Récusation : `controleVote(…, "recuser", …)` puis `recuser`, avec une
  confirmation qui dit qu'elle est définitive et ne retire pas un refus
  (EX-13.5, EX-10.4). Objection et levée : un vote `refuse` ou `approuve`
  sur un ticket à `contest_ms > 0`, nommé comme tel. Retrait : offert
  seulement si `actionRetrait` rend un `by`, avec un motif.
- **Mon adresse** : `annuaire` (document réduit) pour l'état de son entrée
  et de ses adresses ; inscription : découverte, choix du fournisseur,
  `eth_requestAccounts`, choix explicite du compte, `preparer_inscription`,
  `controleDefi` (aucune signature sur un écart), texte affiché ligne par
  ligne, action explicite, `personal_sign` sur `donneesPersonalSign(texte)`,
  `verifierSignature`, `inscrire` ; pannes de la seconde table de 13.14.
- **Annuaire** (session `administrator` vraie ; sinon l'écran le dit et
  n'offre rien) : `annuaire` complet ; par entrée et par adresse, les
  actions d'EX-13.17 et leurs motifs ; avant « Valider », la consigne
  « Avant de valider » d'EX-13.17 ; « Exporter » télécharge le document
  rendu par `annuaire`, octets identiques (`Blob` et lien `download`, à
  éprouver sous la politique d'EX-13.35).
- **Connexion locale** : formulaire nom et mot de passe, envoyé par `fetch`
  (`POST /connexion/locale`, JSON ; `form-action 'none'` interdit l'envoi du
  formulaire lui-même) ; 204 : navigation vers `retour` de l'adresse de
  l'écran, retenu comme en EX-13.43 ; refus : code et, pour `essai_trop_tot`,
  le délai.

### 3.5 Réauthentification avant une signature

Avant `personal_sign`, la page appelle `session` et fait réauthentifier
d'abord quand, `A` étant `auth_time`, `M` l'instant, `W` l'attente admise
(`echeanceAttente`) et 30 s une marge choisie par l'étape 6 :
`reauth_max_age_s > 0` et `M + W + 30 s ≥ A + reauth_max_age_s` ; ou
`reauth_max_age_s = 0` et (une méthode de la liste d'EX-13.8 a été envoyée
par cette page depuis `A`, ou `M + W + 30 s ≥ A + 600 s`). Une signature
obtenue puis refusée par le serveur n'est jamais renvoyée (EX-13.48,
point 5).

### 3.6 Libellés et langue

`<html lang="fr">`. Chaque texte affiché vient de `/statique/libelles/fr.mjs`
(objet figé `{ cle: texte }`, textes à paramètres `{nom}`), par la fonction
`t(cle, valeurs)` de `/statique/commun/libelles.mjs`, qui choisit la table
selon `document.documentElement.lang` ; une table anglaise s'ajoutera par un
fichier `en.mjs` de mêmes clés, sans autre changement. Chaque valeur de
`$defs/code_console`, chaque raison de 12.8, chaque code de
`$defs/code_serveur_console` et chaque avertissement du modèle ont une clé ;
un essai le vérifie contre les énumérations des schémas. Le code reste
affiché entre parenthèses après le texte (EX-13.29).

### 3.7 Essais des pages

Dans Chromium (Playwright 1.56.1), serveur de console et service simulés
par interception des requêtes de la page (même origine HTTPS fictive), ou
par le serveur réel et un service simulé ; fournisseur EIP-1193 simulé
(`test/fixtures/exploitation-console/portefeuille.mjs`, injecté avant le
chargement, annoncé par EIP-6963, signant avec les clés dérivées du
mnémonique de CT-3 A.2) : chaque scénario de la table d'EX-13.36 transposé
aux écrans de 3.1, plus la liste des tickets, `related_to`, l'annuaire
d'administration, l'export, la connexion locale, la réauthentification de
3.5, l'absence de toute requête vers une autre origine et de tout
`window.ethereum` lu.
