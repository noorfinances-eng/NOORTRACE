# Confrontation des fichiers .ots (CT-5, annexe A.6)

`confronter_ots.py` relit les fichiers de `spec/vecteurs/ct-5/ots` sans le
code du dépôt, avec la bibliothèque officielle `python-opentimestamps`,
employée hors ligne :

| Ce qui est recalculé | Par |
|---|---|
| lecture stricte de chaque `.ots`, fin de fichier exacte | `DetachedTimestampFile.deserialize`, `StreamDeserializationContext.assert_eof` |
| **réécriture octet pour octet identique** : l'ordre des branches est celui de la bibliothèque (attestations avant opérations, attestations en attente triées par URI, opérations par étiquette puis argument), que CT-5 EX-6.4 impose à l'écriture | `DetachedTimestampFile.serialize` |
| empreinte du fichier, opération `f0` (append) du nonce de 16 octets puis `08` vers l'engagement `e = SHA-256(empreinte ‖ nonce)`, branches de calendrier (opérations synthétiques `f1` puis `08`, attestation en attente avec son URI), état `en_attente` (EX-6.7) | arbre `Timestamp` de la bibliothèque (`ops`, `attestations`, `all_attestations`) |
| mise à niveau d'EX-6.6 : la réponse du calendrier (`mise-a-niveau.json`, champ `response`) est désérialisée pour l'engagement du nœud en attente (`Timestamp.deserialize`), l'attestation en attente retirée, la réponse fusionnée (`Timestamp.merge`), la preuve resérialisée : octets de `periode-1.ots` de CT-6, état `complete` | `Timestamp.deserialize`, `Timestamp.merge`, `DetachedTimestampFile.serialize` |

Les preuves de la mise à niveau (`o7-en-attente.ots`, `periode-1.ots`) sont
celles de `spec/vecteurs/ct-6/ots/preuves`, lues et non copiées (EX-A.2).
Les preuves des points de contrôle de CT-6 révision 0.2 sont confrontées par
CT-6 (`spec/vecteurs/ct-6/confrontation/ots/`, EX-A.17).

## Exécution

```bash
python3 -m venv <répertoire>/venv
<répertoire>/venv/bin/pip install opentimestamps==0.4.5
<répertoire>/venv/bin/python -I spec/vecteurs/ct-5/confrontation/ots/confronter_ots.py spec/vecteurs/ct-5
```

`pip` installe `opentimestamps` 0.4.5 (licence LGPL-3.0 ou ultérieure, voir
le `LISEZMOI.md` de la confrontation OpenTimestamps de CT-6 pour les
empreintes des paquets). Code de retour : 0 si tout concorde, 1 sinon, 2
pour un usage incorrect. La sortie de référence est `../sorties/ots.txt`
(opentimestamps 0.4.5, Python 3.13) : trois fichiers en attente (12 valeurs
chacun) et la mise à niveau (12 valeurs), 0 discordance.
