# Confrontation des requêtes TimeStampReq (CT-5, annexe A.6)

`confronter_requetes.py` relit les requêtes de `spec/vecteurs/ct-5/requetes`
sans le code du dépôt. Tout ce qui touche au DER est fait par l'exécutable
`openssl` ; le programme (Python, bibliothèque standard seulement) ne fait que
le lancer, lire ses sorties texte et les comparer à `requetes.json` et
`refusees.json`.

| Ce qui est recalculé | Par |
|---|---|
| SHA-256, taille et octets de chaque `.tsq` (égaux au `der` publié) | `openssl dgst -sha256`, lecture du fichier |
| `Version: 1`, `Hash Algorithm: sha256`, les 32 octets du condensé, `Policy OID` (ou `unspecified`), `Nonce`, `Certificate required: yes` (EX-5.1) | `openssl ts -query -in -text` |
| structure DER : suite exacte des éléments (SEQUENCE, INTEGER version, messageImprint avec `NULL` explicite dans l'`AlgorithmIdentifier`, OCTET STRING de 32 octets, `reqPolicy` facultatif, INTEGER du nonce, BOOLEAN `certReq` 255), longueur de l'INTEGER du nonce (9 octets avec `00` de tête pour un nonce à bit haut, 8 sinon), valeur du nonce, OID de la politique | `openssl asn1parse -inform DER` |
| le jeton de CT-1 §11.2 (`reponses/granted-requete-point-k2.der`, SHA-256 `0x0a7cd7a1…9f91`) répond à `requete-point-k2.tsq` : « Verification: OK » (même empreinte, même nonce) ; idem par `-digest <checkpointHash K2>` | `openssl ts -verify -queryfile … -token_in`, `-CAfile ac-test.pem -untrusted tsa-test.pem` (clés de test de CT-6) |
| une requête produite par openssl lui-même sans nonce fait 59 octets et porte les mêmes éléments que celles de CT-5, nonce excepté (EX-8.6, A.8) | `openssl ts -query -digest … -sha256 -cert -no_nonce`, `asn1parse` |
| encodage non minimal du nonce (`refusees.json`, cas `nonce-zero-superflu`) : `openssl ts -query` le refuse (« illegal padding ») ; `asn1parse` relève l'INTEGER de 9 octets pour une valeur à bit haut nul | `openssl ts -query`, `asn1parse` |

Les quatre autres constructions refusées (`condense-31-octets`, `nonce-nul`,
`nonce-hors-64-bits`, `certreq-faux`) le sont par la référence avant tout
encodage : il n'y a aucun octet à confronter (« sans objet »). Une requête
d'openssl **avec** nonce n'est pas confrontée : son nonce est aléatoire et la
sortie publiée doit se rejouer à l'identique.

## Exécution

```bash
python3 -I spec/vecteurs/ct-5/confrontation/requetes/confronter_requetes.py spec/vecteurs/ct-5 "$(mktemp -d)"
```

Code de retour : 0 si tout concorde, 1 sinon, 2 pour un usage incorrect. La
sortie de référence est `../sorties/requetes.txt` (OpenSSL 3.0.13) : six
requêtes, 15 valeurs confrontées par requête (16 avec `reqPolicy`), jeton de
CT-1 §11.2 vérifié, 0 discordance.
