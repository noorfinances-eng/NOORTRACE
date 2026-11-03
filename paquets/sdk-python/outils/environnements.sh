#!/bin/sh
# Environnements d'essai du SDK Python (LISEZMOI, « Environnements d'essai ») :
# un environnement isolé par cadre, créé par `uv` à partir des fichiers de
# verrou versionnés `verrous/requirements-<nom>.txt` (versions exactes,
# empreintes SHA-256 exigées), sous `.environnements/<nom>` (ignoré par git).
#
#   outils/environnements.sh preparer [nom…]     crée les environnements (tous par défaut)
#   outils/environnements.sh verrouiller [nom…]  régénère les fichiers de verrou depuis verrous/<nom>.in
#   outils/environnements.sh liste               noms et versions de Python
#
# `uv` est pris dans UV, à défaut dans PATH. Les environnements des cadres
# emploient Python 3.12 (crewai 1.15.30 exclut 3.14) ; la suite du SDK seul
# s'exécute sous 3.10 (plancher d'EX-6.5) et 3.13.
set -eu

ICI=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UV=${UV:-uv}
TOUS="essais-py310 essais-py313 langchain crewai llamaindex openai-agents litellm litellm-mandataire"

python_de() {
  case "$1" in
    essais-py310) echo 3.10 ;;
    essais-py313) echo 3.13 ;;
    *) echo 3.12 ;;
  esac
}

verrou_de() {
  case "$1" in
    essais-py*) echo essais ;;
    *) echo "$1" ;;
  esac
}

commande=${1:-}
[ $# -gt 0 ] && shift
noms=${*:-$TOUS}

case "$commande" in
  preparer)
    for n in $noms; do
      v=$(python_de "$n")
      f="$ICI/verrous/requirements-$(verrou_de "$n").txt"
      echo "noortrace-sdk : environnement $n (Python $v) depuis $(basename "$f")"
      [ -x "$ICI/.environnements/$n/bin/python" ] || "$UV" venv --quiet --python "$v" "$ICI/.environnements/$n"
      VIRTUAL_ENV="$ICI/.environnements/$n" "$UV" pip sync --quiet --require-hashes "$f"
    done
    ;;
  verrouiller)
    # Depuis verrous/ : les commentaires « via -r <nom>.in » restent relatifs.
    cd "$ICI/verrous"
    for n in $(for x in $noms; do verrou_de "$x"; done | sort -u); do
      "$UV" pip compile --quiet --universal --python-version 3.10 --generate-hashes \
        --custom-compile-command "outils/environnements.sh verrouiller $n" \
        --output-file "requirements-$n.txt" "$n.in"
    done
    ;;
  liste)
    for n in $TOUS; do echo "$n $(python_de "$n") verrous/requirements-$(verrou_de "$n").txt"; done
    ;;
  *)
    echo "usage : outils/environnements.sh preparer|verrouiller|liste [nom…]" >&2
    exit 2
    ;;
esac
