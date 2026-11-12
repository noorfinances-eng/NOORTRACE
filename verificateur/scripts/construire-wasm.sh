#!/usr/bin/env bash
# Construction reproductible de l'artefact WebAssembly noortrace-verifier.wasm
# de la page de vérification (CT-6 §18, EX-18.3, EX-18.4).
#
# Usage : scripts/construire-wasm.sh [-v <version>] -o <répertoire>
#
# Applique la recette d'EX-18.3, et seulement elle : celle d'EX-14.6 avec
# GOOS=js GOARCH=wasm, GOAMD64 omis (sans effet pour GOARCH=wasm) :
#   GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0
#   GOEXPERIMENT= GOFIPS140= GOWASM= \
#   GOOS=js GOARCH=wasm
#   go build -trimpath -buildvcs=false -ldflags='-buildid= -X main.version=<version>' \
#     -o <répertoire>/noortrace-verifier.wasm ./cmd/noortrace-verifier
#
# Le paquet principal est celui des binaires (aucune commande Go propre à la
# page). Le script refuse toute autre chaîne que go1.27.3 (EX-14.3) et ne
# télécharge rien. Il recopie sans changement le fichier de soutien
# $(go env GOROOT)/lib/wasm/wasm_exec.js de la même chaîne dans
# <répertoire>/wasm_exec.js, puis imprime le SHA-256 des deux fichiers
# (EX-18.4 : deux constructions indépendantes doivent donner les mêmes
# octets). <version> est celle des binaires de la version (défaut 0.1.0,
# comme scripts/construire.sh).
set -euo pipefail

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="0.1.0"
sortie=""
while getopts "v:o:" opt; do
  case "$opt" in
    v) version="$OPTARG" ;;
    o) sortie="$OPTARG" ;;
    *) echo "usage : $0 [-v <version>] -o <répertoire>" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
if [ -z "$sortie" ] || [ "$#" -ne 0 ]; then
  echo "usage : $0 [-v <version>] -o <répertoire>" >&2
  exit 2
fi
case "$sortie" in
  /*) ;;
  *) sortie="$PWD/$sortie" ;;
esac

# Variables qui changeraient l'artefact sans être des entrées de la recette
# (niveau de WebAssembly, expériences, module FIPS), que GOENV=off ne
# neutralise pas : la recette les vide (CT-6 0.7, EX-18.3) ; posées dans
# l'environnement, elles sont refusées plutôt qu'écartées en silence.
for variable in GOWASM GOEXPERIMENT GOFIPS140; do
  if [ -n "${!variable:-}" ]; then
    echo "construire-wasm.sh : $variable est posée ($variable=${!variable}) ; la recette d'EX-18.3 la laisse vide" >&2
    exit 1
  fi
done
attendue="go1.27.3"
obtenue="$(GOTOOLCHAIN=local GOENV=off go env GOVERSION)"
if [ "$obtenue" != "$attendue" ]; then
  echo "construire-wasm.sh : Go $attendue exigé (CT-6 EX-14.3, EX-18.3), $obtenue trouvé" >&2
  exit 1
fi
racine_go="$(GOTOOLCHAIN=local GOENV=off go env GOROOT)"
soutien="$racine_go/lib/wasm/wasm_exec.js"
if [ ! -f "$soutien" ]; then
  echo "construire-wasm.sh : fichier de soutien absent : lib/wasm/wasm_exec.js de la chaîne Go" >&2
  exit 1
fi

mkdir -p "$sortie"
cd "$ici"
env GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
  GOEXPERIMENT= GOFIPS140= GOWASM= \
  GOOS=js GOARCH=wasm \
  go build -trimpath -buildvcs=false -ldflags="-buildid= -X main.version=$version" \
  -o "$sortie/noortrace-verifier.wasm" ./cmd/noortrace-verifier
cp "$soutien" "$sortie/wasm_exec.js"
chmod 0644 "$sortie/wasm_exec.js"

(cd "$sortie" && sha256sum noortrace-verifier.wasm wasm_exec.js)
