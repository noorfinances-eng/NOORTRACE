# Confrontation des vecteurs OpenTimestamps (CT-6, annexe A.8)

`confronter_ots.py` recalcule les vecteurs de `spec/vecteurs/ct-6/ots` sans le
code du dépôt, avec la bibliothèque officielle `python-opentimestamps` et
`python-bitcoinlib`, employées hors ligne :

| Ce qui est recalculé | Par |
|---|---|
| lecture stricte des `.ots`, fin de fichier exacte | `DetachedTimestampFile.deserialize`, `StreamDeserializationContext.assert_eof` |
| réécriture identique aux octets du fichier | `DetachedTimestampFile.serialize` |
| empreinte de fichier, opérations, attestations et résultat des opérations | arbre `Timestamp` de la bibliothèque (`ops`, `attestations`) |
| résultat des opérations égal à la racine de Merkle de l'en-tête attesté | `BitcoinBlockHeaderAttestation.verify_against_blockheader` |
| hachage des en-têtes, chaînage, preuve de travail à la cible `regtest` | `CBlockHeader.deserialize`, `GetHash`, `CheckProofOfWork` (paramètres `regtest`), et double SHA-256 de `hashlib` |
| `nNonce` minimal, racines synthétiques, champs fixés par EX-A.6 | `hashlib` |
| URI d'une attestation en attente : 0 à 1000 octets de `A-Z a-z 0-9 - . _ / :` | constantes `PendingAttestation.MAX_URI_LENGTH` et `ALLOWED_URI_CHARS`, appliquées par `deserialize` |
| statuts et raisons de O-1 à O-7, statut du contrôle 5 (EX-10.12), avertissements dans l'ordre de EX-6.15, faits de EX-10.14 | règles de CT-6 §10.4 et §10.5 refaites sur ces primitives |

La bibliothèque refuse `o3-resultat-trop-long.ots` dès la lecture
(`DeserializationError`, résultat de plus de 4096 octets), alors que CT-6
sépare le format (O-1, réussie) des opérations (O-3, en échec). Le programme lit
donc aussi chaque fichier avec les limites de longueur de la bibliothèque
relâchées, et contrôle lui-même les longueurs de 1 à 4096 octets (EX-10.7).

La bibliothèque exécute aussi les opérations hors profil (`03`, RIPEMD-160,
dans `branche-hors-profil.ots`) ; CT-6 ne les exécute pas (EX-10.7). Le
programme relève le résultat que la bibliothèque calcule sous une telle
opération, puis le note `null`, comme le vecteur. Les avertissements sont
comparés comme des listes, dans l'ordre que fixe EX-6.15.

## Exécution

```bash
python3 -m venv <répertoire>/venv
<répertoire>/venv/bin/pip install opentimestamps==0.4.5
<répertoire>/venv/bin/python -I spec/vecteurs/ct-6/confrontation/ots/confronter_ots.py spec/vecteurs/ct-6
```

`pip` installe `opentimestamps` 0.4.5 (licence LGPL-3.0 ou ultérieure :
classificateur « LGPLv3+ » de ses métadonnées, R2-F59), `python-bitcoinlib` 0.12.2 (licence non indiquée dans ses
métadonnées : non vérifié) et `pycryptodomex` 3.24.1. SHA-256 des paquets
relevés le 2026-10-22 : `opentimestamps-0.4.5-py3-none-any.whl`
`a4912b3bd1b612a3ef5fac925b9137889e6c5cb91cc9e76c8202a2bf8abe26b5`,
`python_bitcoinlib-0.12.2-py3-none-any.whl`
`2f29a9f475f21c12169b3a6cc8820f34f11362d7ff1200a5703dce3e4e903a44`.

Code de retour : 0 si tout concorde, 1 sinon. La sortie de référence est
`../sorties/ots.txt` : 112 vérifications O- sur 112 concordantes, aucune
discordance sur les en-têtes, les preuves, les statuts des contrôles, les
avertissements et les faits.
