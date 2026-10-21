# Correctifs sur noorcore

Ce répertoire reçoit les correctifs NOORTRACE à appliquer sur le commit épinglé de
noorchain-core avant la construction du binaire (`chain/scripts/build-noorcore.sh`,
`chain/docker/Dockerfile`). Ils sont fournis hors du dépôt public, parce qu'ils
contiennent des extraits du code de noorchain-core : déposer ici les fichiers
`*.patch` reçus, dans l'ordre de leurs noms, puis construire. Sans correctif, le
binaire construit est celui du commit épinglé, sans la méthode
`noor_getCommitCertificate`.
