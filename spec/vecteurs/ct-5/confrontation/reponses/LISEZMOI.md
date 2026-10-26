# Confrontation des réponses TimeStampResp (CT-5, annexe A.6) et des jetons des points de contrôle (CT-6 EX-A.17)

`confronter_reponses.py` relit les réponses de `spec/vecteurs/ct-5/reponses`
sans le code du dépôt. Tout ce qui touche au DER, aux jetons et aux
signatures est fait par l'exécutable `openssl` ; le programme (Python,
bibliothèque standard seulement) ne fait que le lancer, lire ses sorties
texte et les comparer à `reponses.json` et, pour les dossiers de CT-6, à leur
`attendu.json`.

| Ce qui est recalculé | Par |
|---|---|
| SHA-256 et taille de chaque `.tsr` | `openssl dgst -sha256`, lecture du fichier |
| `Status` (PKIStatus 0 à 5 : Granted., Rejected., Waiting., Revoked.), `Failure info` (texte d'openssl pour chaque `PKIFailureInfo` : `badAlg`, `timeNotAvailable`, `unacceptedPolicy`), présence du `TimeStampToken` | `openssl ts -reply -in -text` |
| champs du `TSTInfo` : `messageImprint` égal à l'empreinte de la requête (lue par `openssl ts -query -text`), nonce (ou `unspecified`), `genTime`, `accuracy` | `openssl ts -reply -text` |
| jeton extrait : SHA-256, taille, octets égaux au `.der` publié | `openssl ts -reply -token_out` |
| verdict d'`openssl ts -verify -queryfile <requête> -in <réponse>` à `genTime`, contre `openssl_verify` de `reponses.json` quand il est donné (« OK », « nonce mismatch ») ; pour les autres cas, le verdict est imprimé à côté du classement de CT-5 | `openssl ts -verify -queryfile … -attime <genTime> -CAfile ac-test.pem -untrusted tsa-test.pem` |
| jetons embarqués en base64 dans les dossiers de CT-6 révision 0.2 (`points-de-controle.json`) : base64 canonique, `messageImprint` égal au `checkpoint_hash` de la partie, « Verification: OK » par `-digest <checkpoint_hash> -token_in`, « FAILED » quand `attendu.json` relève K-7 | `base64` de Python, `openssl ts -reply -token_in -text`, `openssl ts -verify -digest … -token_in -attime <genTime>` |

## Ce qu'OpenSSL ne fait pas

- `accepted_policies` du prestataire (EX-5.10, étape 5) : openssl ne connaît
  pas la liste des politiques admises et `ts -verify` rend « Verification:
  OK » pour `granted-politique-hors-liste`. Le programme confronte donc la
  politique qu'openssl lit dans le `TSTInfo` (`Policy OID`) à
  `accepted_policies` du prestataire de `reponses.json` : hors liste si et
  seulement si CT-5 refuse à l'étape 5 (`politique_refusee`, ou
  `politique_differente` quand la requête portait `reqPolicy`, comparaison
  faite d'abord) ; c'est une concordance, plus une limite. La politique
  **demandée** est contrôlée par openssl lui-même
  (`granted-politique-differente` : « policy mismatch »).
- Fraîcheur et horloge (EX-5.11) : `reponse-tardive-*` et `horloge-suspecte`
  sont des jetons valides pour openssl (« OK ») ; le classement de CT-5 dépend
  des instants d'envoi et de réception, que l'outil ne lit pas.
- Les réponses HTTP représentées (503, 429, 408, 404, 401, type de contenu,
  corps trop long) n'ont pas de corps `TimeStampResp` : sans objet.
- `invalide-k7-base64-non-canonique` : l'altération porte sur l'encodage
  base64 (K-7), pas sur le jeton. Le module `base64` de Python le relève par
  réencodage (« base64 non canonique <=> K-7 attendue en échec » : concorde),
  et openssl confirme que les octets décodés sont ceux d'un jeton valide
  (« Verification: OK »).

## Exécution

```bash
python3 -I spec/vecteurs/ct-5/confrontation/reponses/confronter_reponses.py spec/vecteurs/ct-5 "$(mktemp -d)"
```

Code de retour : 0 si tout concorde, 1 sinon, 2 pour un usage incorrect. La
sortie de référence est `../sorties/reponses.txt` (OpenSSL 3.0.13) : 28 cas
de `reponses.json` (20 réponses DER, 8 réponses HTTP représentées sans
objet), 17 dossiers de CT-6 à partie `points-de-controle.json` (15 jetons
vérifiés, dont ceux du point contresigné de 09:35 et du point de clôture ; 2
sans jeton), 0 discordance, 0 limite de l'outil.

Les raisons d'échec d'openssl sont lues dans son ordre, chacune une fois.
Les erreurs de la bibliothèque système (« system library ») sont écartées :
elles tiennent à l'environnement, pas au jeton. OpenSSL 3.5 en empile une à
chaque échec de vérification (« No such file or directory », pour un
magasin de certificats par défaut absent), qu'OpenSSL 3.0 n'émet pas ; le
verdict comparé reste le même avec les deux versions.
