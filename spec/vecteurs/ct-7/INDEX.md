# Vecteurs CT-7 — sécurité et conformité

Produit par `scripts/vecteurs/generer-ct7.mjs` (`npm run vecteurs:ct7`) ; ne pas
l'éditer à la main. Spécification :
[`spec/CT-7-securite-et-conformite.md`](../../CT-7-securite-et-conformite.md),
annexe A.

Le générateur lit le texte de CT-7 et les vecteurs de CT-1, CT-3, CT-4 et CT-6,
sans jamais les réécrire. Il n'écrit ni n'efface `confrontation/` ni
`verificateur-independant/`. Deux exécutions donnent des fichiers identiques
(EX-A.2).

```bash
npm run vecteurs:ct7
node scripts/conformite/verifier-renvois.mjs                                 # RV-1 à RV-9, MX-1 à MX-9 : code 0
node scripts/verify/ceremonie.mjs spec/vecteurs/ct-7/ceremonies/valide-creation-enregistreur/proces-verbal.json   # code 0
node scripts/conformite/attestation.mjs verifier spec/vecteurs/ct-7/attestations/exemple/attestation-signee.json --jeu spec/vecteurs/ct-7/attestations/exemple/jeu.json
```

## menaces.json

Le modèle de menace de CT-7 §3.8, tiré des tables 3.2 à 3.5 du texte (EX-A.4) :
14 composants, 98 menaces (MN-1 à MN-98), dont 82 avec un risque accepté et 16
sans, 15 tables sources de 151 lignes. Schéma :
`spec/schemas/modele-menace-v0.schema.json`.

| Composant | Menaces |
|---|---|
| `hote_agent` (Hôte de l'agent) | MN-1, MN-2, MN-3, MN-4, MN-5, MN-6 |
| `mandataire_mcp` (Mandataire MCP) | MN-7, MN-8, MN-9, MN-10 |
| `passerelle_modele` (Passerelle du modèle et raccord ICAP) | MN-11, MN-12, MN-13, MN-14 |
| `sdk_otel` (SDK et ingestion OpenTelemetry (chemin déclaratif)) | MN-15, MN-16 |
| `ecrivain_stockage` (Écrivain, stockage et bail) | MN-17, MN-18, MN-19, MN-20, MN-21, MN-22, MN-23, MN-24, MN-25, MN-26, MN-84, MN-85, MN-90 |
| `worm_gel` (Copies WORM et gel juridique) | MN-27, MN-28, MN-29 |
| `cles` (Clés par classe de garde) | MN-30, MN-31, MN-32, MN-33, MN-34, MN-35, MN-36, MN-37, MN-38, MN-39, MN-40, MN-41, MN-42, MN-43, MN-92, MN-93, MN-94, MN-95 |
| `approbation_console` (Service d'approbation et console) | MN-44, MN-45, MN-46, MN-47, MN-48, MN-49, MN-50, MN-51, MN-52 |
| `registre` (Registre (validateurs, RPC, contrats, administrateur, gouvernance, trésorerie)) | MN-53, MN-54, MN-55, MN-56, MN-57, MN-58, MN-59 |
| `ancrage` (Composant d'ancrage, prestataires RFC 3161, calendriers OpenTimestamps) | MN-60, MN-61, MN-62, MN-63, MN-64, MN-65 |
| `verificateur` (Vérificateur et ancres de confiance du réviseur) | MN-66, MN-67, MN-68, MN-69, MN-70, MN-79, MN-80, MN-81, MN-83, MN-89 |
| `exploitant` (Exploitant NOORTRACE) | MN-71, MN-72, MN-73, MN-97 |
| `administrateur_client` (Administrateur du client) | MN-74, MN-75, MN-78, MN-82, MN-86, MN-87, MN-88, MN-91, MN-96, MN-98 |
| `reseau` (Réseau) | MN-76, MN-77 |

### Consolidation des tables sources (CT-7 §3.3)

| Spécification | Section | Ligne de la table source | Menaces de CT-7 |
|---|---|---|---|
| CT-2 | 18.3 | Écrivain | MN-27 |
| CT-2 | 18.3 | Gardien de pose | MN-28 |
| CT-2 | 18.3 | Gardien de levée | MN-28 |
| CT-2 | 18.3 | Lecteur | MN-28 |
| CT-2 | 18.3 | Administrateur du compte | MN-27 |
| CT-3 | 3.5 | Agent (et hôte) | MN-1 |
| CT-3 | 3.5 | Opérateur | MN-23 |
| CT-3 | 3.5 | Administrateur du registre | MN-38 |
| CT-3 | 3.5 | Administrateur du jeu | MN-50 |
| CT-3 | 3.5 | Exploitant du nœud RPC | MN-51 |
| CT-3 | 3.5 | Approbateur malveillant | MN-48 |
| CT-3 | 3.5 | Approbateur contraint | MN-48 |
| CT-3 | 3.5 | Console compromise | MN-45 |
| CT-3 | 3.5 | Extension ou fournisseur malveillant dans le navigateur de l'approbateur | MN-46 |
| CT-3 | 3.5 | Service d'approbation compromis | MN-44 |
| CT-3 | 14.2 | Signature d'un ticket présentée pour un autre ticket, un autre journal, une autre organisation | MN-49 |
| CT-3 | 14.2 | Signature `approuve` présentée comme `refuse`, ou l'inverse | MN-49 |
| CT-3 | 14.2 | Seconde décision pour un ticket décidé | MN-49 |
| CT-3 | 14.2 | Approbation scellée relayée deux fois | MN-5 |
| CT-3 | 14.2 | Approbation scellée relayée pour un autre appel que la demande retenue (« blanchiment ») | MN-5 |
| CT-3 | 14.2 | Approbation scellée réutilisée des semaines plus tard | MN-5 |
| CT-3 | 14.2 | Décision d'une autre demande sous un identifiant réattribué après une perte d'état | MN-49 |
| CT-3 | 14.2 | Signature non canonique (`s` haut) | MN-49 |
| CT-3 | 14.2 | Signature d'une autre forme : `v = 37` ou `38` (EIP-155), signature compacte de 64 octets, `s` haut, `v ∈ {0, 1}` | MN-49 |
| CT-3 | 14.2 | Signature EIP-191 rejouée comme transaction | MN-49 |
| CT-3 | 14.4 | Le service déclare un faux jeu (membres qu'il contrôle) | MN-44 |
| CT-3 | 14.4 | Le jeu change pendant l'attente (membre retiré ou ajouté, seuil changé) | MN-50 |
| CT-3 | 14.4 | L'administrateur du registre réassigne le jeu de l'organisation | MN-38 |
| CT-3 | 14.4 | Un jeu `statique`, écrit par l'opérateur, remplace celui du registre | MN-23 |
| CT-3 | 14.4 | Le nœud RPC sert un état faux | MN-51 |
| CT-3 | 14.5 | La politique et le serveur d'outils lisent des valeurs différentes (grands entiers, décimaux) | MN-4 |
| CT-3 | 14.5 | Clés en double, JSON ambigu, second message caché dans les arguments | MN-4 |
| CT-3 | 14.5 | L'approbateur voit un champ, le serveur en lit un autre (champ inconnu de la règle) | MN-4 |
| CT-3 | 14.5 | Liste d'exclusion à égalité exacte (`egal`, `dans` sous un refus) contournée par une autre écriture de la valeur | MN-4 |
| CT-3 | 14.5 | Le service affiche d'autres arguments que ceux de la demande retenue | MN-44 |
| CT-3 | 14.5 | Arguments modifiés entre la demande et le relais | MN-5 |
| CT-3 | 14.5 | La pièce rédigée ne montre pas le clair : `request_hash` ne lie que la forme rédigée | MN-44 |
| CT-3 | 14.7 | Agent | MN-1 |
| CT-3 | 14.7 | Opérateur de l'agent (demandeur) | MN-48 |
| CT-3 | 14.7 | Approbateur malveillant ou contraint | MN-48 |
| CT-3 | 14.7 | Console compromise, ou émetteur sur le canal console → service | MN-45 |
| CT-3 | 14.7 | Extension ou fournisseur malveillant dans le navigateur de l'approbateur | MN-46 |
| CT-3 | 14.7 | Relais du parcours mobile (13.12) | MN-52 |
| CT-3 | 14.7 | Service d'approbation compromis | MN-44 |
| CT-3 | 14.7 | Administrateur du jeu | MN-50 |
| CT-3 | 14.7 | Administrateur du registre | MN-38 |
| CT-3 | 14.7 | Exploitant du nœud RPC | MN-51 |
| CT-3 | 14.8 | Inscrire l'adresse d'un autre à son nom | MN-47 |
| CT-3 | 14.8 | Faire signer à une personne une inscription de son adresse au nom de l'attaquant (confiscation) | MN-47 |
| CT-3 | 14.8 | Rejouer une preuve | MN-47 |
| CT-3 | 14.8 | Faire prendre une inscription pour un vote, ou l'inverse | MN-47 |
| CT-3 | 14.8 | Administrateur malveillant | MN-47 |
| CT-3 | 14.8 | Session volée (jeton ou cookie de la console) | MN-47 |
| CT-3 | 14.8 | Console compromise | MN-45 |
| CT-3 | 14.8 | Service compromis | MN-44 |
| CT-3 | 14.9 | Un faux portefeuille s'annonce sous le nom, l'icône ou le `rdns` d'un autre (R4-F6) | MN-46 |
| CT-3 | 14.9 | Une extension s'interpose entre la page et le portefeuille et remplace `params[0]` par le `D_A` d'une autre demande | MN-46 |
| CT-3 | 14.9 | Le fournisseur rend une signature forgée, malléable ou d'une autre forme | MN-46 |
| CT-3 | 14.9 | Une bibliothèque encode `D_A` comme la chaîne `"0x…"` | MN-46 |
| CT-3 | 14.9 | Le service sert un événement, une pièce, des champs ou un `D_A` qui ne sont pas ceux de la demande retenue | MN-44 |
| CT-3 | 14.9 | La console est compromise | MN-45 |
| CT-3 | 14.9 | Une console compromise, ou un site tiers, présente comme un vote un condensé du registre de CT-4 (`registerDigest`, `revokeDigest`, `periodDigest`) | MN-45 |
| CT-3 | 14.9 | Un site tiers présente le `D_A` d'un ticket en attente comme un message à signer | MN-46 |
| CT-3 | 14.9 | La page de signature est encadrée par un autre site pour faire cliquer l'approbateur | MN-46 |
| CT-3 | 14.9 | Un clic répété envoie deux requêtes ou deux votes | MN-46 |
| CT-3 | 14.9 | Une signature arrive après le délai, après un changement de décision ou d'adresse, ou après l'ouverture d'un autre ticket | MN-46 |
| CT-3 | 14.9 | Le relais mobile retient, retarde ou observe | MN-52 |
| CT-3 | 14.9 | Le code d'appariement mobile est vu par un tiers | MN-52 |
| CT-3 | 14.9 | Un script de la page lit la clé déchiffrée d'un fichier de clé | MN-35 |
| CT-3 | 14.9 | Canal auxiliaire temporel sur la signature locale du parcours d : la signature de `scripts/lib/console.mjs` (`signerHachage`, appelée par `signerCondense` : ECDSA à nonce RFC 6979 écrit en `BigInt`) n'est pas à temps constant, et la durée de ses multiplications et inversions dépend des bits de la clé et du nonce ; un observateur qui mesure ces durées pourrait en tirer de l'information sur la clé | MN-35 |
| CT-4 | 3.5 | Exploitant | MN-53 |
| CT-4 | 3.5 | Validateurs fautifs, au plus f | MN-54 |
| CT-4 | 3.5 | Client | MN-57 |
| CT-4 | 3.5 | Clé de chaîne compromise | MN-34 |
| CT-4 | 3.5 | Approbateurs au seuil, de connivence | MN-37 |
| CT-4 | 3.5 | Clé de gouvernance compromise | MN-37 |
| CT-4 | 3.5 | Expéditeur sans solde qui atteint un point RPC en écriture : client authentifié mais compromis, poste qui atteint le relais RPC d'un client (10.3), tiers | MN-55 |
| CT-4 | 3.5 | Point RPC ou relais RPC menteur | MN-56 |
| CT-4 | 3.5 | Rejeu | MN-57 |
| CT-4 | 12 | Empoisonnement de la mempool par un expéditeur sans solde : client authentifié mais compromis, poste atteignant le relais RPC d'un client, tiers | MN-55 |
| CT-4 | 12 | Débit d'une clé | MN-55 |
| CT-4 | 12 | Clés des validateurs | MN-39 |
| CT-4 | 12 | Clé de chaîne compromise | MN-34 |
| CT-4 | 12 | Clé de gouvernance compromise, ou approbateurs de connivence | MN-37 |
| CT-4 | 12 | Clé de l'administrateur du registre | MN-38 |
| CT-4 | 12 | Trésorerie | MN-40 |
| CT-4 | 12 | Dossier d'inscription non authentifié | MN-57 |
| CT-4 | 12 | Demande signée rejouée | MN-57 |
| CT-4 | 12 | Substitution d'adresses | MN-57 |
| CT-4 | 12 | Rejeu entre chaînes | MN-57 |
| CT-4 | 12 | Rejeu entre organisations | MN-57 |
| CT-4 | 12 | Empreinte prise | MN-58 |
| CT-4 | 12 | Faille d'un contrat | MN-59 |
| CT-4 | 12 | Réorganisation | MN-59 |
| CT-4 | 12 | Panne d'un validateur | MN-55 |
| CT-4 | 12 | Relais RPC menteur | MN-56 |
| CT-4 | 12 | Validateurs coalisés | MN-54 |
| CT-5 | 3.4 | Opérateur ou enregistreur compromis : détient la clé Ed25519 ou l'usage du signataire | MN-17 |
| CT-5 | 3.4 | Prestataire RFC 3161 malhonnête ou compromis | MN-60 |
| CT-5 | 3.4 | Calendrier OpenTimestamps | MN-62 |
| CT-5 | 3.4 | Fournisseur du registre | MN-54 |
| CT-5 | 3.4 | Intermédiaire réseau entre l'enregistreur et un prestataire, un calendrier ou le registre | MN-76 |
| CT-5 | 3.4 | Composant d'ancrage compromis | MN-63 |
| CT-5 | 13 | Rejeu d'un jeton : un jeton obtenu sur une empreinte est présenté pour une autre, ou une réponse ancienne est renvoyée au client | MN-61 |
| CT-5 | 13 | Prestataire menteur ou compromis : `genTime` faux, antidaté ou postdaté | MN-60 |
| CT-5 | 13 | Horloge de l'enregistreur fausse ou manipulée | MN-21 |
| CT-5 | 13 | Perte ou corruption de la file | MN-64 |
| CT-5 | 13 | Points antidatés ou insérés par qui tient la clé de l'enregistreur | MN-17 |
| CT-5 | 13 | Prestataire injoignable longtemps (jours) | MN-62 |
| CT-5 | 13 | Série réécrite et ancrée à part par qui tient la clé de l'enregistreur et la clé de chaîne | MN-17 |
| CT-5 | 13 | Empreinte prise au registre (`empreinte_squattee`) | MN-58 |
| CT-5 | 13 | Fuite par les empreintes : le prestataire ou le calendrier apprend quelque chose du journal | MN-76 |
| CT-5 | 13 | Secrets d'accès au prestataire (Basic, certificat client) | MN-41 |
| CT-5 | 13 | Déni de service d'un calendrier ou d'un agrégateur OpenTimestamps | MN-62 |
| CT-5 | 13 | Interface du serveur interne exposée | MN-42 |
| CT-5 | 13 | Réponse surdimensionnée ou malformée d'un prestataire ou d'un calendrier | MN-68 |
| CT-6 | 3.4 | Opérateur : le client qui exploite l'agent et l'enregistreur, et qui exporte le dossier | MN-18 |
| CT-6 | 3.4 | Fournisseur NOORTRACE : il exploite le registre et publie le vérificateur | MN-53, MN-54, MN-66, MN-71 |
| CT-6 | 3.4 | Enregistreur compromis : un attaquant détient sa clé Ed25519, sa clé de chaîne, ou les deux | MN-17 |
| CT-6 | 3.4 | Autorité d'horodatage malhonnête ou compromise | MN-60 |
| CT-6 | 3.4 | Validateurs minoritaires : au plus f = ⌊(N − 1)/3⌋ validateurs du jeu du fichier d'ancres | MN-54 |
| CT-6 | 3.4 | Fournisseur d'en-têtes Bitcoin : l'exportateur, ou un mineur | MN-70 |
| CT-6 | 15.5 | Rejeu d'un jeton d'horodatage sur un autre manifeste | MN-61 |
| CT-6 | 15.5 | Jeton d'une TSA que le réviseur n'accepte pas, ou expirée à `genTime` | MN-61 |
| CT-6 | 15.5 | Clé de TSA compromise | MN-60 |
| CT-6 | 15.5 | Rétrogradation d'algorithme | MN-61 |
| CT-6 | 15.5 | Preuve OpenTimestamps d'un autre manifeste | MN-61 |
| CT-6 | 15.5 | Chaîne d'en-têtes sans travail, ou d'un autre réseau | MN-61 |
| CT-6 | 15.5 | Attestation désignant un autre bloc | MN-61 |
| CT-6 | 15.5 | Certificat d'une autre chaîne signé par le même jeu | MN-69 |
| CT-6 | 15.5 | Jeu de validateurs substitué (certificat forgé, `validateurs.json` assorti) | MN-69 |
| CT-6 | 15.5 | En-tête falsifié | MN-69 |
| CT-6 | 15.5 | Reçu falsifié qui garde le `blockHash` certifié | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Point de contrôle du journal qui ne couvre pas l'événement (`tree_size ≤ leaf_index`), ou d'une autre période | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Point d'un autre arbre présenté comme préfixe du manifeste | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Jeton de la clôture, ou d'un autre point, rejoué comme jeton du point | MN-61 |
| CT-6 | 15.5 | (révision 0.2) Preuve OpenTimestamps d'une autre donnée embarquée pour le point | MN-61 |
| CT-6 | 15.5 | (révision 0.2) Référence au registre forgée (empreinte, `docType`, contrat) | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Ancre de période relabellisée en ancre de point | MN-69 |
| CT-6 | 15.5 | (révision 0.2) Ancre de point non incluse présentée comme incluse | MN-69 |
| CT-6 | 15.5 | Événement émis par un autre contrat | MN-69 |
| CT-6 | 15.5 | Clôture ou ancre d'une autre période | MN-69 |
| CT-6 | 15.5 | Ancre absente traitée comme réussie | MN-61 |
| CT-6 | 15.5 | Ancre lue dans le dossier ou sur le réseau | MN-67 |
| CT-6 | 15.5 | Analyseur piégé (longueurs, profondeur, octets en trop, formes non minimales) | MN-68 |
| CT-2 | 18.5 | puce 1 | MN-17, MN-18 |
| CT-2 | 18.5 | puce 2 | MN-17 |
| CT-2 | 18.5 | puce 3 | MN-30 |
| CT-2 | 18.5 | puce 4 | MN-27 |
| CT-2 | 18.5 | puce 5 | MN-27 |
| CT-2 | 18.5 | puce 6 | MN-25 |

## ceremonies/

Chaque cas : `proces-verbal.json` (le fichier vérifié, octets exacts) et
`attendu.json` (`ceremonie-cles-v0#/$defs/attendu`). Un cas invalide est tiré
d'un cas valide par une seule mutation, puis signé de nouveau par tous ses
participants, sauf quand la mutation porte sur les signatures (EX-A.6). Comptes
Hardhat 1 à 8 du mnémonique public de `spec/vecteurs/ct-3/constantes.json`.

| Cas | Mutation | Verdict | En échec | Non exécutées | D_C |
|---|---|---|---|---|---|
| `valide-creation-enregistreur` | exemple de CT-7 §5.10 : création, en production, de la clé de l'enregistreur rec-test-01 (classe A) et de sa clé de chaîne (compte 3) ; officiant, témoin, auditeur : comptes 1, 2, 4 ; écart consigné à l'étape 5 | valide | — | — | `0x737c2975…` |
| `valide-inscription-membres` | production ; officiant et témoin (comptes 1 et 2), membres (comptes 5 et 6), clés d'approbateur réduites à l'adresse, vidéo | valide | — | — | `0x9aa47db2…` |
| `valide-sauvegarde-administrateur-registre` | portée exploitant, org_id nul ; clé administrateur_registre de classe A (compte 3) et clé d'enveloppe, partage 2 sur 3 (détenteurs : comptes 5 à 7) ; officiant de l'exploitant (compte 8) | valide | — | — | `0x62a485a4…` |
| `valide-changement-administrateur` | membres présents du jeu (comptes 1 et 2), nouvelle clé de gouvernance de classe A (compte 7), officiant de l'exploitant (compte 8), témoin (compte 4) | valide | — | — | `0x3de079ca…` |
| `valide-restauration-administrateur-registre` | restauration, en production, de la sauvegarde de valide-sauvegarde-administrateur-registre (purpose_details : son D_C, k = 2, n = 3) : officiant (compte 8), témoin (compte 1), deux détenteurs de part (comptes 5 et 6), aucune clé produite | valide | — | — | `0x31211604…` |
| `valide-rotation-urgence-chaine` | rotation d'urgence de la clé de chaîne de l'exemple, en production : purpose_details avec la décision (07:40) et l'inclusion de la révocation (07:52), nouvelle clé de chaîne (compte 7) ; officiant, témoin, auditeur : comptes 1, 2, 4 | valide | — | — | `0x7d14fe98…` |
| `valide-developpement-classe-d` | développement, clé enregistreur de classe D générée sur le poste, script sans empreinte, sans vidéo ni auditeur | valide | — | — | `0xd995d76d…` |
| `invalide-cr1-cle-en-double` | texte JSON de l'exemple signé avec le membre version en double | invalide | CR-1 | CR-2 à CR-12 | — |
| `invalide-cr1-nombre-non-entier` | texte JSON de l'exemple signé où version vaut 0.0 | invalide | CR-1 | CR-2 à CR-12 | — |
| `invalide-cr1-schema` | membre place retiré | invalide | CR-1 | CR-2 à CR-12 | — |
| `invalide-cr2-un-seul-participant` | seul l'officiant ; les étapes restent témoignées par p2 et p3, qui ne sont plus participants : CR-4 échoue aussi, une seule personne ne pouvant témoigner d'aucune étape (table d'A.4) | invalide | CR-2, CR-4 | — | `0x95d89edd…` |
| `invalide-cr2-deux-officiants` | le témoin p2 devient officiant ; un second témoin p4 (compte 5) le remplace dans chaque étape | invalide | CR-2 | — | `0x82c6a5c1…` |
| `invalide-cr2-adresse-en-double` | l'auditeur p3 a l'adresse du témoin (et signe avec sa clé) | invalide | CR-2 | — | `0xbae42e92…` |
| `invalide-cr2-auditeur-executant` | l'étape 2 est exécutée par l'auditeur p3 | invalide | CR-2 | — | `0xff784614…` |
| `invalide-cr3-etape-avant-le-debut` | at de la première étape avant started_at | invalide | CR-3 | — | `0x53f84d9c…` |
| `invalide-cr3-numerotation` | les deux dernières étapes numérotées 7 | invalide | CR-3 | — | `0x52e6fd29…` |
| `invalide-cr4-temoin-de-lui-meme` | l'officiant p1 parmi les témoins de son étape 2 | invalide | CR-4 | — | `0x9ceaa4ae…` |
| `invalide-cr4-temoin-auditeur-seul` | chaque étape est témoignée par le seul auditeur p3 : aucun témoin de rôle temoin | invalide | CR-4 | — | `0x9b99ce60…` |
| `invalide-cr4-exception-sans-constat` | findings vide alors que l'étape 5 est en exception | invalide | CR-4 | — | `0xa3b1fa2a…` |
| `invalide-cr5-empreinte-fausse` | fingerprint de la clé Ed25519 remplacée par le SHA-256 d'une étiquette | invalide | CR-5 | — | `0x2a979898…` |
| `invalide-cr5-adresse-de-chaine` | address de la clé de chaîne remplacée par celle du compte 1 | invalide | CR-5 | — | `0x17f9e480…` |
| `invalide-cr5-ed25519-33-octets` | clé publique Ed25519 de 33 octets (octet nul ajouté), empreinte recalculée | invalide | CR-5 | — | `0x19fae19d…` |
| `invalide-cr6-classe-d-en-production` | clé enregistreur en classe D, en production | invalide | CR-6 | — | `0xd157b59a…` |
| `invalide-cr6-administrateur-registre-classe-b` | clé administrateur_registre en classe B (cas valide-sauvegarde-administrateur-registre) | invalide | CR-6 | — | `0x0ec2a1b7…` |
| `invalide-cr7-sauvegarde-enregistreur` | partage 2 sur 2 de la clé enregistreur entre deux détenteurs de part ajoutés (comptes 5 et 6) | invalide | CR-7 | — | `0xde222d57…` |
| `invalide-cr7-k-superieur-a-n` | partage de la clé d'enveloppe avec k = 3 et n = 2 (cas valide-sauvegarde-administrateur-registre) | invalide | CR-7 | — | `0xad0b46ac…` |
| `invalide-cr8-membre-sans-cle` | un membre p5 (compte 7) sans clé approbateur (cas valide-inscription-membres) | invalide | CR-8 | — | `0xcc99133f…` |
| `invalide-cr9-sans-video-ni-auditeur` | production sans enregistrement vidéo ni auditeur (cas valide-inscription-membres, vidéo retirée) | invalide | CR-9 | — | `0x820614da…` |
| `invalide-cr9-poste-en-ligne` | clé enregistreur générée sur le poste (generated_in poste), poste en ligne (offline faux) | invalide | CR-9 | — | `0x730baf68…` |
| `invalide-cr10-incident-sans-resolution` | le constat 1 devient un incident sans résolution | invalide | CR-10 | — | `0x2b0fe58b…` |
| `invalide-cr12-details-inattendus` | purpose_details d'une révocation (tx_hash) sur un procès-verbal de création | invalide | CR-12 | — | `0x5a1c1364…` |
| `invalide-cr12-creation-sans-cle` | création sans aucune clé (keys vide) | invalide | CR-12 | — | `0x39265169…` |
| `invalide-cr12-restauration-sans-detenteur` | restauration avec le seul officiant et le seul témoin : les détenteurs p3 et p4 sont retirés (cas valide-restauration-administrateur-registre) | invalide | CR-12 | — | `0x249ce72f…` |
| `invalide-cr12-urgence-ordre` | decided_at postérieur à revocation_included_at (cas valide-rotation-urgence-chaine) | invalide | CR-12 | — | `0x960cffca…` |
| `invalide-cr12-administrateur-sous-seuil` | jeu en vigueur au seuil de 3 avec deux membres présents (cas valide-changement-administrateur) | invalide | CR-12 | — | `0x41cfbd4f…` |
| `invalide-cr11-signature-manquante` | signature de l'auditeur p3 retirée | invalide | CR-11 | — | `0x737c2975…` |
| `invalide-cr11-autre-proces-verbal` | action de l'étape 3 modifiée après signature | invalide | CR-11 | — | `0x577ccdb3…` |
| `invalide-cr11-s-haut` | signature du témoin en forme s haut (n − s, v basculé) | invalide | CR-11 | — | `0x737c2975…` |
| `invalide-cr11-signature-d-une-decision` | le témoin (compte 2) a signé le D_A de la décision apr-1192 de CT-1 §6.4 au lieu de D_C | invalide | CR-11 | — | `0x737c2975…` |
| `invalide-cr11-signataire-substitue` | la signature du témoin est faite par le compte 3 | invalide | CR-11 | — | `0x737c2975…` |

## cles-de-test.json

Les clés publiques de test publiées par les vecteurs (EX-4.10, EX-A.7),
recalculées depuis `ct-1/cles/cles-test.json`, `ct-3/constantes.json` (comptes
Hardhat 0 à 9), `ct-4/constantes.json` et `ct-6/rfc3161/cles/` : 39 clés (ct-1 :
2, ct-3 : 10, ct-4 : 18, ct-6 : 9). Aucune ne sert en production ; RV-9 les
recalcule.

## attestations/

`constantes.json` : `P_P`, comptes, organisation, journaux, étiquette de
`rules_sha256`, jeu. `exemple/` : l'attestation de CT-7 §7.1
(`attestation.json`), `JCS(P)` (`jcs.txt`), `D_P`, `M` et les signatures des
comptes 1 et 2 (`condense.json`), `attestation-signee.json`, `jeu.json`.
`attestations.json` : les cas d'EX-A.8 (schéma
`attestation-perimetre-v0#/$defs/fichier_vecteurs`). `croises.json` : les
signatures croisées d'EX-A.9.

| Cas | AT-1 | AT-2 | AT-3 | AT-4 | Retenue |
|---|---|---|---|---|---|
| `valide-deux-signatures` | reussi | reussi | reussi | reussi | oui |
| `valide-trois-signatures` | reussi | reussi | reussi | reussi | oui |
| `valide-seuil-un` | reussi | reussi | reussi | reussi | oui |
| `invalide-at1-membre-en-trop` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-validite-inversee` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-validite-trop-longue` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-date-inexistante` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-agent-journal-inconnu` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-signataires-en-double` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at1-nombre-non-entier` | echoue | non_execute | non_execute | non_execute | non |
| `invalide-at2-condense-faux` | reussi | echoue | reussi | reussi | non |
| `invalide-at3-signature-substituee` | reussi | reussi | echoue | non_execute | non |
| `invalide-at3-s-haut` | reussi | reussi | echoue | non_execute | non |
| `invalide-at3-v-hors-domaine` | reussi | reussi | echoue | non_execute | non |
| `invalide-at4-seuil-non-atteint` | reussi | reussi | reussi | echoue | non |
| `invalide-at4-non-membre` | reussi | reussi | reussi | echoue | non |
| `invalide-at4-hors-signataires` | reussi | reussi | reussi | echoue | non |
| `invalide-at4-adresse-en-double` | reussi | reussi | reussi | echoue | non |
| `invalide-at4-seuil-incoherent` | reussi | reussi | reussi | echoue | non |

| Signature croisée (compte 1) | Présentée comme | Refusée par | Adresse recouvrée |
|---|---|---|---|
| `decision-comme-attestation` | attestation | CT-1 AT-3 | `0x336f257de6e68d90d80737d289fd251d328280b6` |
| `inscription-comme-attestation` | attestation | CT-1 AT-3 | `0xb0fa917dfa1f2cc55b0a33c3ee3bdd1a8d9f825c` |
| `ceremonie-comme-attestation` | attestation | CT-1 AT-3 | `0x5b5b18920c156ab2540d3f16ed0ee4e14b310e8f` |
| `registre-comme-attestation` | attestation | CT-1 AT-3 | `0x07c41948eabd009e759ffba4bfa228f50ba78380` |
| `attestation-comme-decision` | approbation | CT-1 E-9 | `0xa2da564c46829d0255d403a8ae54d4f3d9a2bf9f` |
| `attestation-comme-inscription` | inscription | CT-3 AN-4 | `0x747b5bb33ee6e79f12101802c6381bfd60e877c0` |
| `attestation-comme-ceremonie` | ceremonie | CT-7 CR-11 | `0x76a0a3c16dde1cd40d0cbd289ebcc1bd7f15ed8d` |

## matrice-conformite.json et matrice/invalides/

La matrice de CT-7 section 8, écrite depuis
`scripts/conformite/matrice-donnees.mjs` : 10 textes, 58 lignes (6 `couvert`, 48
`partiel`, 4 `hors_perimetre`), 6 clauses, 10 lacunes. Schéma :
`spec/schemas/matrice-conformite-v0.schema.json`. C'est une correspondance
technique, pas un avis juridique (EX-8.1). Les cas invalides altèrent la matrice
en un point ; `attendu.json` donne la liste exacte des MX- en échec (MX-8 ne
s'exécute pas sur eux, EX-A.14).

| Cas | Altération | MX- en échec |
|---|---|---|
| `statut-force.json` | MC-57 passe de couvert à partiel | MX-1, MX-3 |
| `couvert-avec-contribution.json` | MC-1 passe à couvert | MX-1, MX-3 |
| `renvoi-inexistant.json` | une pièce de MC-17 devient CT-2 EX-12.999 | MX-4 |
| `section-inexistante.json` | la pièce CT-2 §12.8 de MC-56 devient CT-2 §12.99 | MX-4 |
| `clause-orpheline.json` | la clause CL-5 n'est plus citée par aucune ligne, serves inchangé | MX-5 |
| `lacune-ligne-inconnue.json` | L-1 nomme MC-99 | MX-6 |
| `mot-interdit.json` | le requirement de MC-57 se termine par « : le client est conforme » | MX-7 |
| `ia-sans-date.json` | from de T-8 devient [] | MX-1, MX-9 |
| `texte-inconnu.json` | MC-42 porte text T-11 | MX-2 |
| `fait-hors-annexe.json` | MC-1 cite R6-F99 | MX-9 |
| `lignes-permutees.json` | les lignes MC-25 et MC-26 échangent leur place | MX-2 |
| `ia-date-passee.json` | from de T-8 reçoit en tête une date passée, 2026-08-02 | MX-9 |

## Épreuves à l'aveugle (section 9)

| Épreuve | Remis à la personne | Grille, non remise |
|---|---|---|
| Responsable de la sécurité (EX-9.1) | `acceptation-securite/consigne.md` | `acceptation-securite-attendu.json` |
| Responsable de la conformité (EX-9.2, EX-9.3) | `acceptation-conformite/consigne.md` | `acceptation-conformite-attendu.json` (dérivée de `matrice-conformite.json`) |
| Administrateur du client (EX-9.4, EX-9.5) | `acceptation-attestation/consigne.md`, `acceptation-attestation/rapport.txt` | `acceptation-attestation-attendu.json` |

Les consignes d'EX-9.1 et d'EX-9.2 remettent CT-7 sans sa section 9 ni son
annexe A.15, qui portent les grilles. `acceptation-attestation/rapport.txt` est
la sortie lisible de `node scripts/verify/dossier.mjs
spec/vecteurs/ct-1/dossiers/valide-seq-12-attestation-inscrite`, sans les lignes
« Vérificateur : » et « Répertoire : », qui dépendent de la machine (EX-A.29).
Grilles : `modele-menace-v0#/$defs/grille_securite`,
`matrice-conformite-v0#/$defs/grille_conformite`,
`attestation-perimetre-v0#/$defs/grille_attestation`.
