#!/usr/bin/env bash
# Construction reproductible du binaire noortrace-verifier (CT-6 EX-14.6).
#
# Usage : scripts/construire.sh [-v <version>] [-o <sortie>] [-p <GOOS>/<GOARCH>]
#
# Applique la recette de référence d'EX-14.6, et seulement elle :
#   GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0
#   GOEXPERIMENT= GOFIPS140= \
#   GOOS=<os> GOARCH=<arch> GOAMD64=v1
#   go build -trimpath -buildvcs=false -ldflags='-buildid= -X main.version=<version>' -o <sortie> ./cmd/noortrace-verifier
#
# Entrées pertinentes, et seules entrées : les sources, la version exacte de
# Go (go1.27.3, EX-14.3), GOOS, GOARCH et le niveau d'architecture, vendor/
# avec modules.txt. Le script refuse toute autre version de Go et ne
# télécharge rien (GOTOOLCHAIN=local, GOPROXY=off). GOEXPERIMENT et
# GOFIPS140, que GOENV=off ne neutralise pas et qui changent le binaire, sont
# vidées par la recette (CT-6 0.7, EX-14.6) ; le script refuse de construire
# quand l'une est posée dans son environnement, plutôt que de l'écarter en
# silence.
#
# Il imprime le SHA-256 du binaire produit (EX-14.8 : deux constructions
# indépendantes doivent donner les mêmes octets).
set -euo pipefail

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="0.1.0"
sortie=""
plateforme="linux/amd64"
while getopts "v:o:p:" opt; do
  case "$opt" in
    v) version="$OPTARG" ;;
    o) sortie="$OPTARG" ;;
    p) plateforme="$OPTARG" ;;
    *) echo "usage : $0 [-v <version>] [-o <sortie>] [-p <GOOS>/<GOARCH>]" >&2; exit 2 ;;
  esac
done
goos="${plateforme%/*}"
goarch="${plateforme#*/}"
if [ -z "$sortie" ]; then
  sortie="$ici/dist/noortrace-verifier-$goos-$goarch"
fi
case "$sortie" in
  /*) ;;
  *) sortie="$PWD/$sortie" ;;
esac

for variable in GOEXPERIMENT GOFIPS140; do
  if [ -n "${!variable:-}" ]; then
    echo "construire.sh : $variable est posée ($variable=${!variable}) ; la recette d'EX-14.6 la laisse vide" >&2
    exit 1
  fi
done
attendue="go1.27.3"
obtenue="$(GOTOOLCHAIN=local GOENV=off go env GOVERSION)"
if [ "$obtenue" != "$attendue" ]; then
  echo "construire.sh : Go $attendue exigé (CT-6 EX-14.3), $obtenue trouvé" >&2
  exit 1
fi

mkdir -p "$(dirname "$sortie")"
cd "$ici"
env GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
  GOEXPERIMENT= GOFIPS140= \
  GOOS="$goos" GOARCH="$goarch" GOAMD64=v1 \
  go build -trimpath -buildvcs=false -ldflags="-buildid= -X main.version=$version" -o "$sortie" ./cmd/noortrace-verifier

sha256sum "$sortie"
