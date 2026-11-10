# Confrontation des vecteurs RFC 3161 (CT-6, annexe A.8)

`confronter_rfc3161.py` recalcule les vecteurs de `spec/vecteurs/ct-6/rfc3161`
sans le code du dépôt. Tout ce qui touche au DER, aux certificats, aux CRL, aux
empreintes et aux signatures est fait par l'exécutable `openssl` ; le programme
(Python, bibliothèque standard seulement) ne fait que le lancer, lire ses
sorties texte et les comparer à `rfc3161/attendu.json`.

| Ce qui est recalculé | Par |
|---|---|
| SHA-256 des certificats (DER), des clés (PKCS #8 DER), des CRL et des jetons ; taille des clés ; clé publique de chaque certificat égale à celle de sa clé | `openssl x509`, `pkcs8 -topk8`, `pkey`, `crl`, `dgst` |
| signature et contenu des CRL de test (émetteur, `thisUpdate`, entrée révoquée pour `keyCompromise`) | `openssl crl -CAfile` |
| champs de `TSTInfo` : empreinte, `genTime`, numéro de série, version, politique, précision, nonce, `tsa`, extensions | `openssl ts -reply -token_in -text` |
| structure CMS : versions, `SignerInfo`, `eContentType`, algorithmes | `openssl cms -cmsout -print` |
| lecture DER du fichier entier, octets de `eContent`, `message-digest`, `certHash` ESS ; champs de `TSTInfo` d'un jeton qu'`openssl ts` refuse | `openssl asn1parse` (et `-strparse`) |
| certificat lisible ou non ; valeur DEFAULT encodée (`BOOLEAN :0`, X.690 §11.5) dans un certificat ou dans `TSTInfo` ; clé publique de chaque certificat | `openssl x509`, `openssl crl2pkcs7 -certfile`, `openssl asn1parse` (et `-strparse`), `openssl pkey -pubin` |
| longueur DER non minimale dans un certificat ou dans la `RSAPublicKey` de sa clé (`hl` imprimé supérieur à l'en-tête minimal pour `l`) ; extension connue indécodable (`WARNING code=-1` de `X509_check_purpose`, `ossl_x509v3_cache_extensions`) : défauts de lecture selon CT-6 §9.3 qu'OpenSSL lit sans les refuser (révision 0.5, EX-A.25) | `openssl asn1parse` (et `-strparse` de la `BIT STRING` du `SubjectPublicKeyInfo`), `openssl x509 -purpose` |
| vérification du jeton à `genTime` contre l'autorité de test | `openssl ts -verify -digest <periodHash> -token_in -CAfile ac-test.pem -attime <genTime>` |
| politique admise | `openssl ts -verify -queryfile` sur une requête portant la politique de l'ancre |
| signature des seuls attributs signés ; vérification CMS complète | `openssl cms -verify` (`-noverify -no_content_verify`, puis `-purpose timestampsign`) |
| chemin à `genTime`, usage horodatage | `openssl verify -partial_chain -attime`, `openssl verify -purpose timestampsign` |
| autorité retenue (règle « Chemin retenu » de EX-9.13), chemin, faits de EX-9.19 | `openssl verify -partial_chain -show_chain`, autorité par autorité dans l'ordre du fichier d'ancres |
| révocation | `openssl verify -crl_check -attime <thisUpdate>` |

## Ce qu'OpenSSL ne fait pas

- T-5 (algorithmes admis) : OpenSSL n'applique pas la table des algorithmes
  admis de EX-9.11 ; `openssl ts -verify` accepte le jeton `t5-sha1.der`, signé
  en SHA-1. Le programme rapporte les algorithmes qu'OpenSSL lit ; la
  vérification est « hors outil ».
- T-11 (statut qualifié déclaré par le réviseur) : « hors outil ».
- T-1 : `openssl ts -verify` et `openssl cms -verify` ignorent l'octet qui suit
  le `ContentInfo` de `t1-octet-en-trop.der` ; `openssl asn1parse` le relève
  (« Error in encoding »).
- T-9 : `openssl ts -verify` accepte l'extension critique inconnue de
  `t9-extension-critique.der` (OpenSSL 3.0.13) ; `openssl ts -text` la lit et
  l'imprime « critical ».
- T-10 : OpenSSL juge « not yet valid » une CRL dont `thisUpdate` suit
  `-attime` ; la règle de EX-9.16 exige au contraire `thisUpdate` postérieur
  ou égal à `genTime`. La révocation du certificat signataire est donc
  vérifiée à `thisUpdate` ; OpenSSL refuse alors toute révocation, quelles qu'en
  soient la raison et la date, et ne départage pas les cas de EX-9.16.
- `openssl cms -verify` ne contrôle pas les attributs ESS (`t4` y passe) ;
  `openssl ts -verify` les contrôle (« ess cert id not found »).
- T-1, valeur DEFAULT encodée : OpenSSL lit sans la refuser une extension
  dont `critical` vaut FALSE encodé explicitement (`tsa-critique-faux.pem`,
  jeton `t1-default-explicite.der` : `openssl ts -verify` répond
  « Verification: OK »). `openssl asn1parse` imprime ce champ
  (« BOOLEAN :0 ») ; le programme applique X.690 §11.5 à cette sortie, comme
  EX-9.21. Le paquet `crypto/x509` de Go 1.24.7 l'accepte aussi
  (`parseExtension`, `src/crypto/x509/parser.go`, lignes 205 à 209, lu).
- T-1, longueur non minimale (révision 0.5) : OpenSSL lit
  `tsa-cle-longueur-non-minimale.pem`, dont la `RSAPublicKey` porte une
  longueur longue non minimale, et `openssl ts -verify` répond
  « Verification: OK » pour `t1-cle-longueur-non-minimale.der` ; `openssl
  asn1parse -strparse` de la clé imprime `hl=5` pour une valeur de 394 octets,
  qui tient sur quatre. Le programme relève toute longueur dont l'en-tête
  dépasse le minimum (X.690 §10.1) dans la sortie d'`asn1parse` du certificat et
  de sa clé, et tient le certificat pour illisible (T-1), comme EX-9.4.
- T-1, extension connue mal formée (révision 0.5) : OpenSSL lit
  `tsa-extension-mal-formee.pem` (valeur de `keyUsage` en `INTEGER`) et
  `openssl ts -text` lit le jeton `t1-extension-mal-formee.der` ; `openssl
  x509 -text` imprime la valeur sans la décoder, `openssl x509 -purpose`
  signale `WARNING code=-1` (certificat marqué invalide par
  `ossl_x509v3_cache_extensions`) et `openssl ts -verify` échoue
  (« certificate verify error »). Le programme tient ce certificat pour
  illisible (T-1), comme EX-9.7.
- T-1, nom illisible : OpenSSL refuse de lire `tsa-cn-utf8-invalide.pem` et
  le jeton `t1-cn-utf8-invalide.der` (« invalid utf8string ») ; c'est aussi
  la règle de EX-9.4. `openssl x509` ne donne que la raison de son chargeur
  (« unsupported ») : `openssl crl2pkcs7 -certfile` donne celle du décodage.
- T-7, unité épinglée : OpenSSL n'admet un certificat non autosigné comme
  ancre de confiance qu'avec `-partial_chain`, option employée pour T-7.
  Quand le fichier d'ancres déclare l'unité et son AC, OpenSSL construit le
  chemin le plus long (jusqu'à l'AC autosignée) ; EX-9.13 retient la première
  autorité de l'ordre du fichier pour laquelle un chemin existe. Le
  programme essaie donc chaque autorité seule, dans cet ordre.
- T-10, CRL d'une unité épinglée : EX-9.16 prend la CRL du fichier d'ancres
  qui vise le certificat d'une autorité sans en vérifier la signature ;
  OpenSSL ne lit une CRL qu'avec le certificat de son émetteur. Le programme
  ajoute donc `cles/ac-test.pem`, émetteur des certificats et des CRL de
  test, au `-CAfile` de la vérification de révocation.

## Exécution

```bash
python3 -I spec/vecteurs/ct-6/confrontation/rfc3161/confronter_rfc3161.py spec/vecteurs/ct-6 "$(mktemp -d)"
```

Code de retour : 0 si tout concorde, 1 sinon. La sortie de référence est
`../sorties/rfc3161.txt` (OpenSSL 3.0.13) : 265 concordances vérification par
vérification, 0 discordance, 75 vérifications hors outil (T-5 et T-11),
89 sans objet (vérifications que le vecteur n'exécute pas par dépendance ou
faute d'ancre, ou qu'OpenSSL ne peut établir sur un jeton qu'il ne lit pas),
et 8 verdicts d'`openssl ts -verify` qui ne disent pas ce que dit
`attendu.json` (T-1 deux fois, T-5 trois fois, T-7, T-9, et le jeton Ed25519
de la révision 0.4) pour les raisons ci-dessus et ci-dessous.

## Révision 0.2 (points de contrôle, EX-A.17)

Les jetons `jetons/point-periode-1.der` et `jetons/k7-point-signature.der`
(empreinte : le `checkpoint_hash` du point, nonce dérivé de l'étiquette
`…/nonce-tsa/point-de-controle/periode-1`) sont lus et vérifiés comme les
autres (`openssl ts -verify -digest <checkpoint_hash> -token_in -attime
<genTime>` : « Verification: OK », puis « signature failure » pour le jeton
altéré). Les jetons embarqués en base64 dans les dossiers qui portent la
partie `points-de-controle.json` sont confrontés par CT-5
(`spec/vecteurs/ct-5/confrontation/reponses/`, section 2 de sa sortie), qui
les extrait du base64 et lance la même commande.

## Révision 0.4 (EX-A.22)

Les clés et jetons nouveaux sont confrontés comme les autres. Chaque clé est
lue par `openssl pkey -text` (taille, exposant public, ou type Ed25519) et
chaque certificat par `openssl x509`, sa clé publique comparée à celle de sa
clé (`tsa-8200.pem`, `tsa-8192.pem`, `tsa-exposant.pem`,
`intermediaire-8200.pem`, `tsa-ed25519.pem`, `tsa-ed25519-auto-signe.pem` ;
`tsa-par-intermediaire-8200.pem` porte la clé de `tsa-test`). Le certificat
signataire est le candidat (certificats du jeton, puis ceux des autorités du
fichier d'ancres) dont le SHA-256 égale le `certHash` ESS ; T-4 passe ces
candidats des ancres à `openssl ts -verify` par `-untrusted`, et relève
« signer certificate not found » (`t4-sid-introuvable.der`,
`t4-sans-certificat.der` sans intermédiaire ; avec
`ancres-unite-intermediaire.json`, le jeton sans certificats se vérifie).

Ce qu'OpenSSL ne fait pas, en plus de ce qui précède :

- EX-9.23 : OpenSSL vérifie sous une clé RSA de 8200 bits ou d'exposant
  2^31 + 1 (`openssl ts -verify` : « Verification: OK » pour
  `t5-rsa-8200.der`, `t5-exposant.der` et `t7-intermediaire-rsa-8200.der`).
  T-5 reste « hors outil » ; pour T-7, le programme lit la clé de chaque
  certificat candidat (`openssl x509 -text`), écarte ceux dont la clé RSA est
  hors des bornes (module de 2048 à 8192 bits, exposant impair de 3 à
  2^31 − 1) et laisse `openssl verify -partial_chain` chercher un chemin avec
  les autres : sans l'intermédiaire de 8200 bits, aucun chemin.
- EX-9.24 : `openssl ts -verify` ne vérifie pas la signature Ed25519 d'un
  jeton (« signature failure » : « operation not supported for this keytype »
  avec OpenSSL 3.0.13, « invalid eddsa instance for attempted operation » avec
  OpenSSL 3.5.5 ; le résultat présumé ne retient que le motif commun), là où le
  vecteur `t5-cle-ed25519.der` ne relève aucun échec (T-5 à T-7, T-10, T-11
  non exécutées, `hors_perimetre_version`) ; `openssl cms -verify` la vérifie.
  Pour `t5-algorithme-inconnu.der`, OpenSSL ignore l'identifiant inconnu de
  `signatureAlgorithm` et échoue sur la signature altérée.
- EX-9.15 : le numéro de série de 168 bits de `serie-168-bits.der` est lu et
  accepté (« Verification: OK »).
