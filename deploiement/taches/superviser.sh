#!/usr/bin/env bash
# Services de supervision de référence de NOORTRACE (CT-8 §10.3, EX-10.3,
# EX-10.5, EX-10.7 ; revue de sécurité de l'étape 8 : aucune unité ne lançait l'extracteur ni la
# sonde), lancés par les unités noortrace-extracteur.service et
# noortrace-sonde.service (deploiement/taches/systemd/, posées par
# poser-taches.sh --supervision) sous le compte noortrace-supervision, distinct
# de chaque composant supervisé, en lecture seule sur les journaux.
#
#   superviser.sh extracteur [--afficher]
#   superviser.sh sonde [--afficher]
#
# Les réglages viennent de l'environnement (/etc/noortrace/taches.env, modèle
# taches.env.modele) : NOORTRACE_RACINE, NOORTRACE_SUPERVISION (répertoire du
# collecteur textfile), NOORTRACE_SUPERVISION_INTERVALLE (défaut 15 s, EX-10.7),
# NOORTRACE_PROJET et NOORTRACE_VOLUMES (racine des volumes du moteur : les
# journaux lus sont <volumes>/<projet>_exploitation/_data et
# <volumes>/<projet>_approbation-etat/_data), NOORTRACE_SAUVEGARDES et
# NOORTRACE_EXPLOITATION/proces-verbaux (procès-verbaux), NOORTRACE_EXTRACTEUR_*
# (chemins supplémentaires, séparés par des espaces), NOORTRACE_SONDE_*
# (approbation, console, points RPC <cible>=<url>, manifeste d'instance).
# Seuls les chemins qui existent au lancement sont passés à l'extracteur (un
# chemin qui apparaît ensuite est pris au prochain redémarrage du service).
# L'extracteur écrit <supervision>/extracteur.prom, la sonde <supervision>/sonde.prom,
# chacun avec son témoin de vie (noortrace_extracteur_derniere_passe_s,
# noortrace_sonde_derniere_passe_s). --afficher imprime la commande, un
# argument par ligne, sans la lancer. Codes : 2 usage ou réglage manquant ;
# sinon le processus est remplacé par l'outil (exec).

set -uo pipefail
export LC_ALL=C

service="${1:-}"
afficher=0
[ "${2:-}" != "--afficher" ] || afficher=1
case "$service" in
  extracteur|sonde) [ $# -le 2 ] || { echo "Usage : superviser.sh <extracteur|sonde> [--afficher]" >&2; exit 2; } ;;
  *) echo "Usage : superviser.sh <extracteur|sonde> [--afficher]" >&2; exit 2 ;;
esac

racine="${NOORTRACE_RACINE:-}"
supervision="${NOORTRACE_SUPERVISION:-}"
intervalle="${NOORTRACE_SUPERVISION_INTERVALLE:-15}"
projet="${NOORTRACE_PROJET:-noortrace}"
volumes="${NOORTRACE_VOLUMES:-/var/lib/docker/volumes}"
exploitation="${NOORTRACE_EXPLOITATION:-/srv/noortrace-exploitation}"
sauvegardes="${NOORTRACE_SAUVEGARDES:-/srv/noortrace-sauvegardes}"

for v in racine supervision; do
  if [ -z "${!v}" ]; then
    echo "Erreur : NOORTRACE_$(printf '%s' "$v" | tr '[:lower:]' '[:upper:]') non réglé (/etc/noortrace/taches.env)" >&2
    exit 2
  fi
done
case "$intervalle" in ''|*[!0-9]*|0) echo "Erreur : NOORTRACE_SUPERVISION_INTERVALLE : entier de secondes, au moins 1" >&2; exit 2 ;; esac
racine="${racine%/}"

commande=()
case "$service" in
  extracteur)
    commande=(node "$racine/scripts/deploiement/extraire-journaux.mjs")
    # ajouter <option> <chemin…> : chaque chemin qui existe.
    ajouter() {
      local option="$1" c
      shift
      for c in "$@"; do [ -z "$c" ] || [ ! -e "$c" ] || commande+=("$option" "$c"); done
    }
    ajouter --exploitation "$volumes/${projet}_exploitation/_data"
    ajouter --approbation "$volumes/${projet}_approbation-etat/_data/journal-service.ndjson"
    ajouter --proces-verbaux "$sauvegardes" "$exploitation/proces-verbaux"
    # shellcheck disable=SC2086
    ajouter --gel ${NOORTRACE_EXTRACTEUR_GEL:-}
    # shellcheck disable=SC2086
    ajouter --acquisitions ${NOORTRACE_EXTRACTEUR_ACQUISITIONS:-}
    # shellcheck disable=SC2086
    ajouter --registre ${NOORTRACE_EXTRACTEUR_REGISTRE:-}
    # shellcheck disable=SC2086
    ajouter --consultations ${NOORTRACE_EXTRACTEUR_CONSULTATIONS:-}
    if [ ${#commande[@]} -eq 2 ]; then
      echo "Erreur : aucun journal à lire n'existe (volumes sous $volumes, procès-verbaux sous $sauvegardes)" >&2
      exit 2
    fi
    ;;
  sonde)
    commande=(node "$racine/scripts/deploiement/sonde.mjs" --approbation "${NOORTRACE_SONDE_APPROBATION:-http://127.0.0.1:8601}")
    [ -z "${NOORTRACE_SONDE_CONSOLE:-}" ] || commande+=(--console "$NOORTRACE_SONDE_CONSOLE")
    for r in ${NOORTRACE_SONDE_RPC:-}; do commande+=(--rpc "$r"); done
    [ -z "${NOORTRACE_SONDE_INSTANCE:-}" ] || commande+=(--instance "$NOORTRACE_SONDE_INSTANCE")
    ;;
esac
commande+=(--sortie "$supervision/$service.prom" --intervalle "$intervalle")

if [ "$afficher" -eq 1 ]; then
  printf '%s\n' "${commande[@]}"
  exit 0
fi
[ -d "$supervision" ] || { echo "Erreur : répertoire de supervision absent : $supervision" >&2; exit 2; }
exec "${commande[@]}"
