#!/bin/sh
# Environnements Python des scénarios d'intégration de CT-9 TI-4 à TI-11
# (test/integrations.test.js) : un environnement isolé par SDK ou cadre, créé
# par `uv` à partir des fichiers de verrou versionnés
# `test/fixtures/integrations/verrous/requirements-<nom>.txt` (versions exactes,
# empreintes SHA-256 exigées, aucune distribution publiée après la date
# d'exclusion), sous `paquets/sdk-python/.environnements/integration-<nom>`
# (ignoré par git), à côté des environnements des adaptateurs
# (paquets/sdk-python/outils/environnements.sh).
#
#   test/fixtures/integrations/environnements.sh preparer [nom…]     crée les environnements (tous par défaut)
#   test/fixtures/integrations/environnements.sh verrouiller [nom…]  régénère les verrous depuis verrous/<nom>.in
#   test/fixtures/integrations/environnements.sh liste               noms, Python et verrou
#
# `uv` est pris dans UV, à défaut dans PATH. Python 3.12, comme les
# environnements des cadres. La date d'exclusion (`--exclude-newer`) tient la
# règle « rien de publié depuis moins de deux semaines » pour chaque
# distribution résolue, directe ou transitive ; elle est fixée au jour du
# verrouillage moins quatorze jours et inscrite en tête de chaque verrou.
set -eu

ICI=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RACINE=$(CDPATH= cd -- "$ICI/../../.." && pwd)
ENVS="$RACINE/paquets/sdk-python/.environnements"
UV=${UV:-uv}
TOUS="anthropic gemini langchain llamaindex otel"
PYTHON=3.12
EXCLURE_APRES=${NOORTRACE_VERROU_EXCLURE_APRES:-2026-10-30T00:00:00Z}

commande=${1:-}
[ $# -gt 0 ] && shift
noms=${*:-$TOUS}

case "$commande" in
  preparer)
    for n in $noms; do
      f="$ICI/verrous/requirements-$n.txt"
      d="$ENVS/integration-$n"
      echo "noortrace-integrations : environnement integration-$n (Python $PYTHON) depuis $(basename "$f")"
      [ -x "$d/bin/python" ] || "$UV" venv --quiet --python "$PYTHON" "$d"
      VIRTUAL_ENV="$d" "$UV" pip sync --quiet --require-hashes "$f"
    done
    ;;
  verrouiller)
    cd "$ICI/verrous"
    for n in $noms; do
      "$UV" pip compile --quiet --universal --python-version 3.10 --generate-hashes \
        --exclude-newer "$EXCLURE_APRES" \
        --custom-compile-command "test/fixtures/integrations/environnements.sh verrouiller $n (distributions publiées avant le $EXCLURE_APRES seulement)" \
        --output-file "requirements-$n.txt" "$n.in"
    done
    ;;
  liste)
    for n in $TOUS; do echo "integration-$n $PYTHON test/fixtures/integrations/verrous/requirements-$n.txt"; done
    ;;
  *)
    echo "usage : test/fixtures/integrations/environnements.sh preparer|verrouiller|liste [nom…]" >&2
    exit 2
    ;;
esac
