#!/usr/bin/env bash
# Exécution d'une tâche planifiée de NOORTRACE (CT-8 EX-8.6, TP-1 à TP-8 ;
# EX-11.24, sauvegarde) par le minuteur du système (unités systemd de
# deploiement/taches/systemd/, posées par poser-taches.sh).
#
#   executer-tache.sh <TP-1 … TP-8 | SAUVEGARDE>
#
# Les réglages viennent de l'environnement (fichier /etc/noortrace/taches.env,
# modèle taches.env.modele, lu par l'unité). Chaque exécution ajoute à
# NOORTRACE_TACHES_JOURNAL une ligne JSON horodatée avec son code de sortie
# (EX-8.6) :
#   {"ts":"…","task":"TP-6","exit_code":0,"duration_ms":412,"detail":"…"}
# Ce fichier se range avec le journal (CT-8 §11.2) : il est sous
# NOORTRACE_EXPLOITATION, que la sauvegarde emporte.
# Le code de sortie est celui de la commande de la tâche ; 3 : tâche sans
# commande configurée (aucun outil du dépôt pour TP-2, TP-3 et TP-5 : la
# commande est celle du client) ; 2 : usage ou réglage manquant.

set -uo pipefail
export LC_ALL=C

tache="${1:-}"
racine="${NOORTRACE_RACINE:-}"
exploitation="${NOORTRACE_EXPLOITATION:-/srv/noortrace-exploitation}"
journal_taches="${NOORTRACE_TACHES_JOURNAL:-$exploitation/taches/taches.ndjson}"
projet="${NOORTRACE_PROJET:-noortrace}"

horodatage() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
ms() { date +%s%3N; }
json_texte() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }

consigner() {
  local code="$1" duree="$2" detail="$3"
  install -d -m 0750 "$(dirname "$journal_taches")"
  printf '{"ts":"%s","task":"%s","exit_code":%d,"duration_ms":%d,"detail":"%s"}\n' \
    "$(horodatage)" "$(json_texte "$tache")" "$code" "$duree" "$(json_texte "$detail")" >> "$journal_taches"
}

requis() {
  local v
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "Erreur : $v non réglé (/etc/noortrace/taches.env)" >&2
      return 2
    fi
  done
}

volume() { docker volume inspect -f '{{ .Mountpoint }}' "${projet}_$1"; }

dc() {
  docker compose --project-directory "$racine/deploiement" -f "$racine/deploiement/${NOORTRACE_COMPOSE:-compose/production.yaml}" "$@"
}

commande_client() {
  local variable="$1"
  if [ -z "${!variable:-}" ]; then
    echo "Erreur : $variable non réglée : aucun outil du dépôt pour $tache, la commande est celle du client" >&2
    return 3
  fi
  bash -c "${!variable}"
}

executer() {
  case "$tache" in
    TP-1)
      # Gel de la période close (CT-8 EX-11.17) par le gardien de pose, hors du démon :
      # conteneur éphémère de l'image de l'enregistreur, identifiants du gardien montés en lecture.
      requis NOORTRACE_RACINE NOORTRACE_TP1_IDENTIFIANTS NOORTRACE_TP1_IDENTITE || return $?
      local p=$(( ( $(date -u +%s) / 3600 - 1 ) * 3600 ))
      dc run --rm --no-deps -T \
        -v "$NOORTRACE_TP1_IDENTIFIANTS:/run/noortrace-gardien/identifiants:ro" \
        --entrypoint /usr/local/bin/noortrace-ctl enregistreur \
        worm gel poser --configuration /etc/noortrace/configuration.json \
        --identifiants '{"file":"/run/noortrace-gardien/identifiants"}' \
        --identite "$NOORTRACE_TP1_IDENTITE" --de "$p" --a "$p" --motif "TP-1 gel de la periode close $p"
      ;;
    TP-2) commande_client NOORTRACE_TP2_COMMANDE ;;
    TP-3) commande_client NOORTRACE_TP3_COMMANDE ;;
    TP-4)
      # Relecture des gels avec les identifiants du Lecteur, hors du démon (CT-2 EX-17.7).
      requis NOORTRACE_RACINE NOORTRACE_TP4_IDENTIFIANTS NOORTRACE_TP4_GELS || return $?
      local g code=0
      for g in $NOORTRACE_TP4_GELS; do
        dc run --rm --no-deps -T \
          -v "$NOORTRACE_TP4_IDENTIFIANTS:/run/noortrace-lecteur/identifiants:ro" \
          --entrypoint /usr/local/bin/noortrace-ctl enregistreur \
          worm gel etat --configuration /etc/noortrace/configuration.json \
          --identifiants '{"file":"/run/noortrace-lecteur/identifiants"}' --gel "$g" || code=$?
      done
      return $code
      ;;
    TP-5) commande_client NOORTRACE_TP5_COMMANDE ;;
    TP-6)
      # Fichiers tournés du journal d'exploitation (CT-8 EX-11.22, EX-11.23).
      requis NOORTRACE_RACINE NOORTRACE_INSTANCE || return $?
      local rep
      rep="$(volume exploitation)" || return 2
      node "$racine/scripts/deploiement/archiver-journal-exploitation.mjs" \
        --journal "$rep/${NOORTRACE_OPS_LOG:-exploitation.ndjson}" --instance "$NOORTRACE_INSTANCE" \
        --vers "$exploitation/journal-exploitation"
      ;;
    TP-7)
      # Exercice annuel de rotation d'urgence et de révocation (CT-7 EX-3.12) : acte humain.
      echo "TP-7 : exercice de rotation d'urgence et de révocation dû (CT-7 EX-3.12 ; RB-8) ; procès-verbal de cérémonie à produire"
      ;;
    TP-8)
      # Contrôle préalable de production rejoué (CT-8 section 6).
      requis NOORTRACE_RACINE NOORTRACE_STOCKAGE NOORTRACE_IP_INTERNE || return $?
      install -d -m 0750 "$exploitation/controles"
      local sortie="$exploitation/controles/TP-8-$(date -u +%Y%m%dT%H%M%SZ).json"
      local dim=()
      [ -z "${NOORTRACE_DIMENSIONNEMENT:-}" ] || dim=(--dimensionnement "$NOORTRACE_DIMENSIONNEMENT")
      (cd "$racine/deploiement" && node ../scripts/deploiement/controle-prealable.mjs --profil production \
        --configuration config/production/configuration.json --ancrage config/production/ancrage.json \
        --compose compose/production.yaml --images images/images.json --secrets secrets \
        --stockage "$NOORTRACE_STOCKAGE" "${dim[@]}" --ip-interne "$NOORTRACE_IP_INTERNE" \
        --declare cache-protege --json > "$sortie")
      ;;
    SAUVEGARDE)
      # Archive quotidienne et procès-verbal `sauvegarde` (CT-8 EX-11.2, EX-11.24).
      requis NOORTRACE_RACINE NOORTRACE_ORG_ID NOORTRACE_JOURNAL_ID NOORTRACE_CLES || return $?
      local rep jour rang id dest
      rep="$(volume journal)" || return 2
      dest="${NOORTRACE_SAUVEGARDES:-/srv/noortrace-sauvegardes}"
      install -d -m 0700 "$dest"
      jour="$(date -u +%Y-%m-%d)"
      rang=$(( $(find "$dest" -maxdepth 1 -name "pv-$jour-*.json" ! -name '*.verification-journal.json' | wc -l) + 1 ))
      id="pv-$jour-$(printf '%03d' "$rang")"
      node "$racine/scripts/deploiement/sauvegarde.mjs" creer \
        --journal "$rep/${NOORTRACE_ORG_ID#0x}/${NOORTRACE_JOURNAL_ID#0x}" --cles "$NOORTRACE_CLES" \
        --archive "$dest/noortrace-$id.tar" --pv "$dest/$id.json" --id "$id" \
        --executant "${NOORTRACE_SAUVEGARDE_IDENTITE:-tache-sauvegarde}" --motif "sauvegarde quotidienne, tache SAUVEGARDE" \
        --source "volume ${projet}_journal, hote $(hostname)" --destination "archive noortrace-$id.tar, $dest"
      ;;
    *)
      echo "Erreur : tâche inconnue ${tache:-(aucune)} (TP-1 à TP-8, SAUVEGARDE)" >&2
      return 2
      ;;
  esac
}

case "$tache" in
  TP-[1-8]|SAUVEGARDE) ;;
  *) echo "Usage : executer-tache.sh <TP-1 … TP-8 | SAUVEGARDE>" >&2; exit 2 ;;
esac
racine="${racine%/}"
debut="$(ms)"
sortie_tache="$(executer 2>&1)"
code=$?
printf '%s\n' "$sortie_tache"
consigner "$code" "$(( $(ms) - debut ))" "$(printf '%s' "$sortie_tache" | tail -n 1 | cut -c1-500)"
exit "$code"
