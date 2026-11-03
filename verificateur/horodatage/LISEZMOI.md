# Paquet `horodatage` : contrôle 4 et K-7

Ce paquet vérifie un jeton d'horodatage RFC 3161 selon CT-6 §9 : les onze
vérifications T-1 à T-11 sur `jeton-rfc3161.der` (contrôle 4), les mêmes sur
le jeton embarqué dans `points-de-controle.json` (K-7, EX-9.22), et le profil
DER strict de §9.3 appliqué aux certificats et aux CRL du fichier d'ancres
(`ControleurAncres`, N-1, EX-12.2). Le contrat est dans `../INTERFACES.md`,
section « Contrôle 4 » ; `interface.go` n'est pas modifié.

| Fichier | Contenu |
|---|---|
| `der.go` | Lecteur DER borné (§9.3, EX-9.4) : étiquettes et longueurs selon `cryptobyte`, BOOLEAN `00`/`ff`, profondeur 32, noms (UTF8String valide, BMPString paire), temps, extensions. |
| `certificat.go` | Certificats et CRL lus strictement (EX-9.21 : `critical`, `cA`, `version` encodés à leur valeur `DEFAULT`) ; `ControleurAncres`. |
| `jeton.go` | `ContentInfo`, `SignedData`, `SignerInfo`, `TSTInfo` (T-1, EX-9.7). |
| `algorithmes.go` | Identifiants de §9.4, table d'EX-9.11, clés, vérification des signatures (`crypto/rsa`, `crypto/ecdsa`). |
| `instant.go` | `genTime` à pleine précision, `genTime + accuracy`, bornes d'EX-9.15. |
| `verifier.go` | T-1 à T-6, T-8, T-9, T-11, statut d'EX-9.18, faits d'EX-9.19, proposition d'EX-9.20, AV-T- et AV-K-. |
| `chemin.go` | T-7 (chemin à `genTime`, EX-9.13) et T-10 (révocation, EX-9.16). |

Aucune entrée-sortie, aucun appel à `x509.Certificate.Verify` : `crypto/x509`
ne sert qu'à lire une clé publique ECDSA (`ParsePKIXPublicKey`, EX-14.4).
Toute récursion est bornée par la profondeur DER ; la recherche de chemin
calcule ses niveaux en largeur (n ≤ 4) avec les signatures en cache.

Tests : `vecteurs_test.go` rejoue les 24 cas de
`spec/vecteurs/ct-6/rfc3161/attendu.json` (statuts, avertissements, faits) ;
`dossiers_test.go` rejoue la part du contrôle 4 et de K-7 des 73 dossiers de
`spec/vecteurs/ct-6/dossiers` (sans dépendre des contrôles 5 et 8) ;
`controles_test.go` exerce chaque vérification en réussite et en échec sur des
jetons fabriqués (`fabrique_test.go`, clés de test publiques de
`rfc3161/cles`) ; `robustesse_test.go` couvre N-1, les entrées hostiles et
les cibles de fuzzing `FuzzJeton`, `FuzzCertificat`, `FuzzCRL`.

## Révision 0.4 de CT-6

Le paquet applique les règles de la révision 0.4 propres au contrôle 4 et à
K-7 :

- **EX-9.10** : un `sid` qui ne désigne aucun candidat fait échouer T-4 dès
  que le fichier d'ancres porte une autorité d'horodatage ou que le jeton
  porte le champ `certificates` (même vide) ; seul un jeton sans
  certificats, vérifié sans autorité, laisse T-4 `ancre_absente`. Le détail
  nomme le `sid` et le nombre de candidats examinés (`t4SansCandidat`).
- **EX-9.23** : clé RSA de 2048 à 8192 bits, exposant impair de 3 à
  2³¹ − 1, contrôlés sur la clé avant toute vérification (`lireCle`), pour
  la clé de S (T-5), celles du chemin et de l'autorité (T-7) et celle d'une
  CRL (T-10, CRL écartée avec AV-T-3).
- **EX-9.24** : clé et algorithme qui ne vont pas ensemble, T-5 en échec ;
  clé d'un type hors de la version 0 sous un algorithme qui ne l'est pas
  non plus : `hors_perimetre_version` si le certificat de l'unité se
  rattache à une autorité par les règles 1 à 7 d'EX-9.13 (`rattachement`),
  échec sinon, `ancre_absente` sans autorité ; résumé « signature hors de la
  version 0, non vérifiée : aucune date établie ».
- **EX-9.15** : `serialNumber` de toute taille et de tout signe, sans effet
  sur T-9 (le paquet était conforme).

## Lectures

Points où CT-6 ne tranche pas, ou que les vecteurs précisent ; la lecture
retenue est celle du code.

1. **Format de `serial_number`** (EX-9.19, « hexadécimal `0x` »). L'exemple
   de §8.6 (`facts.checkpoint.timestamp`) et la liste `tokens` de
   `rfc3161/attendu.json` écrivent `0x3e9` pour le numéro 1001 ; les `facts`
   du cas `jetons/point-periode-1.der` du même fichier écrivent `0x03e9`.
   Lecture : les octets de valeur de l'INTEGER tels qu'encodés, en
   hexadécimal minuscule complet (EX-6.11, CT-1 §3), soit `0x03e9`, comme les
   faits de l'attendu.
2. **`serialNumber`** : tranché par EX-9.15 (révision 0.4) : ni sa taille
   ni son signe ne sont contrôlés, il est rapporté tel qu'encodé.
3. **AV-T-4 sans `accuracy`** (§9.7). Comparé à `genTime` seul (un sous-champ
   absent vaut zéro, EX-9.15). AV-T-4 est levé par T-9 dès que les règles 1,
   2, 4 et 5 tiennent, avant la règle 3 ; AV-T-2 dès que T-9 s'exécute.
4. **`anchors_used`** (EX-9.22, INTERFACES.md) : l'autorité retenue par T-7,
   puis, dans l'ordre du fichier, les CRL de l'ancre retenues comme preuve
   pour un certificat du chemin et celles qui listent le certificat de
   l'autorité (elles décident de T-10). Une déclaration
   (`revocation.statements`) employée n'y figure pas : ni CT-6 ni
   INTERFACES.md ne la nomment.
5. **AV-T-3** : au plus un par CRL, dans l'ordre du fichier d'ancres puis du
   champ `crls` du jeton. « Émise pour un certificat du chemin » se lit :
   émetteur égal à celui d'un cᵢ. Une CRL qui ne concerne que le certificat
   de l'autorité et qui n'est pas complète n'est pas consultée et ne lève
   rien. Une CRL du jeton dont l'encodage casse le DER du jeton fait échouer
   T-1 (le jeton n'est pas lisible selon §9.3) ; une `SEQUENCE` bien formée
   qui n'est pas une CRL lisible lève AV-T-3 ; un `RevocationInfoChoice`
   `other [1]` n'est pas une CRL et n'est pas consulté.
6. **Preuve rapportée** (`revocation` d'EX-9.19) : pour chaque cᵢ, la
   première CRL retenue (fichier d'ancres puis jeton), sinon la première
   déclaration ; l'unité épinglée (n = 0 par identité) n'a rien à prouver et
   `revocation` est vide.
7. **`digestAlgorithms` de `SignedData`** : lu comme un `SET OF
   AlgorithmIdentifier`, jamais comparé (EX-9.7 ne le nomme pas, et il n'est
   pas signé).
8. **Algorithme « admis par T-5 » pour un certificat ou une CRL** (règle 3
   de T-7, règle 1 de T-10) : la table d'EX-9.11, clé de l'émetteur comprise
   (RSA de 2048 à 8192 bits et d'exposant impair de 3 à 2³¹ − 1, EX-9.23 ;
   P-256, P-384, P-521) ; `rsaEncryption`, qui ne
   nomme pas de fonction de hachage, n'est pas admis pour signer un
   certificat. Les paramètres « absents ou `NULL` » sont admis pour tous les
   algorithmes, ECDSA compris. RSASSA-PSS : longueur de sel lue dans les
   paramètres (20 par défaut, RFC 4055).
9. **Candidats de T-4 « distincts »** : comparés par leur DER ; un même
   certificat présent dans le jeton et dans l'ancre ne compte qu'une fois.
10. **Profondeur DER 32** : comptée pour chaque structure lue depuis sa
    racine : le jeton depuis son `ContentInfo`, le `TSTInfo` depuis sa
    `SEQUENCE`, un certificat ou une CRL du fichier d'ancres depuis la
    sienne, une valeur d'extension décodée depuis la sienne.
11. **Versions** : un certificat sans champ `version` (v1 implicite) est
    lisible s'il ne porte pas d'extension ; seule la valeur v1 *encodée* est
    refusée (EX-9.21). Une CRL de `version` 0 ou 1, ou sans version, est
    lisible.
12. **`tsu_subject_cn`** : `PrintableString`, `IA5String`, `TeletexString`
    et `NumericString` sont décodées comme ISO 8859-1 (identique à l'ASCII
    pour leurs caractères admis) ; une valeur vide donne `null` (le schéma
    du rapport exige une chaîne non vide).
13. **ESS** : les règles 1 à 3 d'EX-9.10 s'appliquent à chacun des deux
    attributs présents ; AV-T-1 (T-4) est levé quand le `hashAlgorithm` du
    premier `ESSCertIDv2` est SHA-256, avec ou sans paramètres `NULL`. Une
    valeur ESS illisible fait échouer T-4 (EX-9.7 ne la range pas dans T-1).
14. **T-9, règle 3 non évaluée** : T-9 prend la raison de T-4, ou
    `prerequis_en_echec` si T-4 a échoué (EX-5.5).

Hors de ce paquet, signalé sans modification : `cmd/noortrace-verifier`
affiche toujours, sans condition, l'avertissement « binaire provisoire […]
N-1 n'applique pas encore le profil DER strict » (`avertissementProvisoire`),
devenu inexact pour N-1.
