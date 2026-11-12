# NOORTRACE {{version}} — note de version

Commit : `{{commit}}`
Date du commit (`SOURCE_DATE_EPOCH` = {{epoch}}) : {{date}}

Cette note est publiée hors des serveurs qui servent les fichiers et les
images (CT-8 EX-3.14) : comparer chaque fichier téléchargé aux valeurs
ci-dessous, jamais à un fichier pris sur le serveur de téléchargement.

## Fichiers de la version

| Fichier | Octets | SHA-256 |
|---|---|---|
{{table_fichiers}}

Vérifier tous les fichiers à la fois :

```bash
sha256sum --strict -c SHA256SUMS
```

## Signature de `SHA256SUMS`

`SHA256SUMS` est signé par minisign (CT-6 EX-14.9) ; le commentaire de
confiance porte la version et la date :

```text
trusted comment: {{commentaire_confiance}}
```

```bash
minisign -Vm SHA256SUMS -P <clé publique publiée par le porteur>
```

{{etat_signature}}

## Binaire `noortrace-verifier` (CT-6 §14)

| Plate-forme | SHA-256 |
|---|---|
| `linux/amd64` | `{{sha_amd64}}` |
| `linux/arm64` | `{{sha_arm64}}` |

Recette (CT-6 EX-14.6), go1.27.3 exactement (EX-14.3), depuis un clone au
commit ci-dessus :

```bash
cd verificateur
scripts/construire.sh -v {{version}} -p linux/amd64 -o noortrace-verifier-linux-amd64
scripts/construire.sh -v {{version}} -p linux/arm64 -o noortrace-verifier-linux-arm64
```

Image de construction (CT-6 EX-14.7) : {{image_construction}}

Sortie attendue de `go version -m` (CT-6 EX-14.9) :

```text
{{go_version_m_amd64}}
```

```text
{{go_version_m_arm64}}
```

Licences : `LICENSE` (Apache-2.0), `NOTICE`, `LICENCES-TIERCES` (Go,
`golang.org/x/crypto` avec `PATENTS`, decred ; CT-6 EX-14.10).

## Archive de déploiement (CT-8 EX-3.6)

`{{nom_archive}}` : SHA-256 `{{sha_archive}}`, {{taille_archive}} octets,
{{entrees_archive}} fichiers, archive ustar déterministe (CT-8 EX-13.14 :
entrées triées, mode `0644`, propriétaires nuls, date du commit).

```bash
echo '{{sha_archive}}  {{nom_archive}}' | sha256sum -c
mkdir noortrace && tar -xkf {{nom_archive}} -C noortrace && cd noortrace/deploiement
(cd .. && sha256sum --strict -c SHA256SUMS --quiet)
```

## Images `noortrace/*` (CT-8 EX-3.13 à EX-3.15)

| Image | Étiquette | Condensé |
|---|---|---|
{{table_images}}

## Provenance

{{etat_provenance}}
