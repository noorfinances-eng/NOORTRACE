# scripts/publication — version préparée, rien de publié

Préparation des fichiers d'une version de NOORTRACE (CT-6 §14.3 et §14.4,
CT-8 EX-3.6, EX-3.13, EX-3.14). Ni le script ni le travail de CI ne
publient, ne signent ni ne poussent quoi que ce soit : la publication reste
un acte du porteur du projet, fait après relecture des fichiers préparés.

| Fichier | Rôle |
|---|---|
| `preparer-version.mjs` | Écrit sous `--sortie` les binaires `noortrace-verifier` `linux/amd64` et `linux/arm64` (recette de `verificateur/scripts/construire.sh`), leur `go version -m`, l'archive de déploiement `noortrace-deploiement-<version>.tar` (ustar déterministe de CT-8 EX-13.14), `LICENSE`, `NOTICE`, `LICENCES-TIERCES`, `SHA256SUMS`, la déclaration de provenance in-toto préparée (non signée) et la note de version |
| `note-de-version.gabarit.md` | Gabarit de la note de version, rempli par le script (marques `{{…}}`) |
| `../../.github/workflows/version.yml` | Travail de CI : à la main (`workflow_dispatch`) ou sur une étiquette `v*` ; droits `contents: read` seulement ; deux constructeurs indépendants (image `golang` épinglée par condensé, go1.27.3 officiel vérifié par SHA-256), puis le script avec `--temoin` ; résultat en artefacts de l'exécution seulement |

## Essai à blanc, sur un poste

go1.27.3 sur le `PATH`, `npm ci` fait, aucun réseau :

```bash
node scripts/publication/preparer-version.mjs --version 0.1.0 \
  --commit "$(git rev-parse HEAD)" --date "$(git log -1 --format=%ct)" \
  --sortie /chemin/hors/du/depot/noortrace-0.1.0
cd /chemin/hors/du/depot/noortrace-0.1.0 && sha256sum --strict -c SHA256SUMS
```

`--date` est la date du commit (`SOURCE_DATE_EPOCH`) : mêmes entrées, mêmes
octets. Un arbre de travail modifié ou un `--commit` autre que `HEAD` est
signalé ; `--exiger-arbre-propre` (employé par la CI) le refuse. L'essai
`test/publication-etape7.test.js` rejoue deux préparations et compare leurs
octets.

## Publication, après validation (non faite)

Chaque pas ci-dessous demande un accord du porteur et n'est pas outillé
dans le dépôt :

1. Relire les artefacts de l'exécution de `version.yml` : les deux
   constructeurs sont égaux (sinon le travail a échoué), `SHA256SUMS` se
   vérifie, la note est complète ; reconstruire au moins un binaire sur une
   autre machine et comparer (`sha256sum --strict -c SHA256SUMS`).
2. Signer `SHA256SUMS` hors de la CI, avec la clé minisign du porteur, le
   commentaire de confiance de la note (version et date) :
   `minisign -S -s <clé secrète> -m SHA256SUMS -t '<commentaire>'`, puis
   `minisign -Vm SHA256SUMS -P <clé publique>`.
3. Attestation signée de provenance : ajouter au travail `preparation` les
   droits `id-token: write` et `attestations: write` et une étape
   d'attestation des fichiers de `SHA256SUMS`, épinglée par SHA de commit
   comme les autres actions.
4. Publier la note hors des serveurs de téléchargement, puis les fichiers et
   `SHA256SUMS.minisig` ; renseigner les condensés des images `noortrace/*`
   publiées (`--condenses`).
