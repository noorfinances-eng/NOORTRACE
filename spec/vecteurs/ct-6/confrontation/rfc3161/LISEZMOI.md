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
`../sorties/rfc3161.txt` (OpenSSL 3.0.13) : 141 concordances vérification par
vérification, 0 discordance, 39 vérifications hors outil (T-5 et T-11),
40 sans objet (vérifications que le vecteur n'exécute pas par dépendance ou
faute d'ancre, ou qu'OpenSSL ne peut établir sur un jeton qu'il ne lit pas),
et 4 verdicts d'`openssl ts -verify` qui ne relèvent pas l'échec visé (T-1
deux fois, T-5, T-9) pour les raisons ci-dessus.
