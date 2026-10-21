#!/usr/bin/env bash
# Construit le binaire noorcore de l'instance NOORTRACE depuis le commit épinglé.
#
#   bash chain/scripts/build-noorcore.sh            # saute si le binaire existe
#   bash chain/scripts/build-noorcore.sh --force    # reconstruit quoi qu'il arrive
#
# Ce que fait le script :
#   1. si chain/runtime/bin/noorcore existe déjà et que --force n'est pas donné,
#      il ne fait rien (le binaire en place est réputé issu du commit épinglé) ;
#   2. sinon, il clone à profondeur 1 le commit épinglé de noorchain-core dans
#      chain/runtime/src/noorchain-core (s'il n'y est pas déjà, auquel cas il
#      vérifie que la copie est bien au commit attendu) ;
#   3. puis il lance `go build ./core` et dépose le binaire dans
#      chain/runtime/bin/noorcore.
#
# Variables d'environnement (facultatives) :
#   NOORTRACE_RUNTIME_DIR   répertoire d'exécution (défaut : chain/runtime)
#   NOORTRACE_NOORCORE_SRC  copie de travail de noorchain-core déjà présente,
#                           utilisée en lecture seule à la place du clone ; elle
#                           doit être exactement au commit épinglé
#
# Prérequis : git, Go (le go.mod de noorchain-core impose go 1.26.9 ; avec
# GOTOOLCHAIN=auto, la chaîne de compilation est téléchargée si besoin).

set -euo pipefail

NOORCORE_REPO="https://github.com/noorfinances-eng/noorchain-core.git"
NOORCORE_COMMIT="618fcef8805ef5b4cb9291a3dd97be710e489297"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
chain_dir="$(cd -- "$script_dir/.." >/dev/null 2>&1 && pwd)"
RUNTIME_DIR="${NOORTRACE_RUNTIME_DIR:-$chain_dir/runtime}"
case "$RUNTIME_DIR" in /*) ;; *) RUNTIME_DIR="$PWD/$RUNTIME_DIR" ;; esac
BIN="$RUNTIME_DIR/bin/noorcore"
SRC="${NOORTRACE_NOORCORE_SRC:-$RUNTIME_DIR/src/noorchain-core}"
case "$SRC" in /*) ;; *) SRC="$PWD/$SRC" ;; esac

force=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    -h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "build-noorcore: option inconnue : $arg (attendu : --force)" >&2; exit 2 ;;
  esac
done

if [[ -x "$BIN" && "$force" -eq 0 ]]; then
  echo "build-noorcore: binaire déjà présent, construction sautée : $BIN (passer --force pour reconstruire)"
  exit 0
fi

command -v git >/dev/null 2>&1 || { echo "build-noorcore: git introuvable" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "build-noorcore: go introuvable" >&2; exit 1; }

# --- source : clone à profondeur 1 du commit épinglé, ou copie fournie -------
if [[ -d "$SRC/.git" ]]; then
  tete="$(git -C "$SRC" rev-parse HEAD)"
  if [[ "$tete" != "$NOORCORE_COMMIT" ]]; then
    echo "build-noorcore: $SRC est au commit $tete, pas au commit épinglé $NOORCORE_COMMIT ; refus de construire" >&2
    echo "  (supprimer ce répertoire pour recloner, ou pointer NOORTRACE_NOORCORE_SRC vers une copie au bon commit)" >&2
    exit 1
  fi
  echo "build-noorcore: source au commit épinglé : $SRC"
elif [[ -n "${NOORTRACE_NOORCORE_SRC:-}" ]]; then
  echo "build-noorcore: NOORTRACE_NOORCORE_SRC=$SRC n'est pas une copie git" >&2
  exit 1
else
  echo "build-noorcore: clone à profondeur 1 du commit $NOORCORE_COMMIT dans $SRC…"
  mkdir -p "$SRC"
  git -C "$SRC" init -q
  git -C "$SRC" remote add origin "$NOORCORE_REPO"
  git -C "$SRC" fetch -q --depth 1 origin "$NOORCORE_COMMIT"
  git -C "$SRC" checkout -q --detach FETCH_HEAD
  tete="$(git -C "$SRC" rev-parse HEAD)"
  [[ "$tete" == "$NOORCORE_COMMIT" ]] || { echo "build-noorcore: le clone est au commit $tete, attendu $NOORCORE_COMMIT" >&2; exit 1; }
fi

# --- construction ------------------------------------------------------------
mkdir -p "$(dirname "$BIN")"
echo "build-noorcore: go build ./core (depuis $SRC)…"
(cd "$SRC" && go build -o "$BIN" ./core)
echo "build-noorcore: binaire construit : $BIN ($(go -C "$SRC" version | awk '{print $3}'), commit $NOORCORE_COMMIT)"
