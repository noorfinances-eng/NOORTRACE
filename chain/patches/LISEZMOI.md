# Correctifs sur noorcore

Ce répertoire reçoit les correctifs NOORTRACE à appliquer sur le commit épinglé de
noorchain-core avant la construction du binaire (`chain/scripts/build-noorcore.sh`,
`chain/docker/Dockerfile`). Ils sont fournis hors du dépôt public, parce qu'ils
contiennent des extraits du code de noorchain-core : déposer ici les fichiers
`*.patch` reçus, dans l'ordre de leurs noms, puis construire. Sans correctif, le
binaire construit est celui du commit épinglé, sans la méthode
`noor_getCommitCertificate`.

Le `.gitignore` de ce répertoire ignore tout fichier autre que ce LISEZMOI et
lui-même : un correctif déposé ici n'est jamais suivi par git (vérifier par
`git check-ignore -v chain/patches/<nom>.patch`), et il se retire après la
construction.

## Empreintes des correctifs (CT-4 EX-10.1 c, d)

Le fichier suivi `EMPREINTES` nomme chaque correctif attendu avec son SHA-256,
au format de `sha256sum` ; il ne porte jamais le contenu d'un correctif. Avant
tout `git apply`, `chain/scripts/build-noorcore.sh` et `chain/docker/Dockerfile`
lancent `chain/scripts/verifier-correctifs.sh` : la construction s'arrête si une
empreinte diffère, si un correctif listé manque ou si un fichier `*.patch` non
listé est présent ; trois binaires ne peuvent plus porter la même étiquette. Une
construction sans aucun correctif n'est admise qu'en le demandant
(`NOORTRACE_SANS_CORRECTIF=1`, `--build-arg NOORTRACE_SANS_CORRECTIF=1`) et sous
une autre étiquette que `noortrace/noorcore:618fcef-noortrace` : le binaire n'a
alors pas `noor_getCommitCertificate`. Un correctif nouveau ou changé se déclare
par une nouvelle ligne d'`EMPREINTES` dans le même commit que la nouvelle
étiquette de l'image (`chain/docker/README.md`).
