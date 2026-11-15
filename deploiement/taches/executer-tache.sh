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
# Ce fichier est sous NOORTRACE_EXPLOITATION, sur l'hôte ; l'archive de
# sauvegarde de 11.2 n'emporte que le répertoire du journal (revue de sécurité de l'étape 8 :
# révision d'EX-11.22 demandée) : la copie des archives d'exploitation hors
# de l'hôte reste à l'outil du client.
# Le code de sortie est celui de la commande de la tâche ; 3 : tâche sans
# commande configurée (aucun outil du dépôt pour TP-2, TP-3 et TP-5 : la
# commande est celle du client) ; 2 : usage ou réglage manquant.
#
# Supervision (CT-8 EX-10.9, EX-11.24 ; revue de sécurité de l'étape 8) : quand
# NOORTRACE_SUPERVISION (répertoire du collecteur textfile de l'exportateur
# de nœud) est réglé, les relectures hors du composant passent par
# « sonde.mjs releve », qui écrit noortrace_releve_externe_ok{check} et
# noortrace_releve_externe_dernier_s{check} dans releve-<check>.prom et rend
# le code de la relecture : TP-4 (check registre_gels), TP-5 (console) et la
# relecture de TP-6 (copie_exploitation, archiver --verifier après la copie).
# Chaque exécution écrit en outre tache-<id>.prom : noortrace_tache_code{task}
# (code de sortie) et noortrace_tache_derniere_s{task} (fin, secondes UNIX),
# pour qu'une règle voie une tâche en échec ou qui ne tourne plus. Sans
# NOORTRACE_SUPERVISION, rien n'est écrit hors du journal des tâches.

set -uo pipefail
export LC_ALL=C

tache="${1:-}"
# Second argument interne « --relecture » : exécute la seule relecture de la tâche (commande
# enveloppée par sonde.mjs releve), sans consigner ; employé par la tâche elle-même.
relecture=0
[ "${2:-}" != "--relecture" ] || relecture=1
racine="${NOORTRACE_RACINE:-}"
exploitation="${NOORTRACE_EXPLOITATION:-/srv/noortrace-exploitation}"
journal_taches="${NOORTRACE_TACHES_JOURNAL:-$exploitation/taches/taches.ndjson}"
projet="${NOORTRACE_PROJET:-noortrace}"
supervision="${NOORTRACE_SUPERVISION:-}"

horodatage() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
ms() { date +%s%3N; }
json_texte() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }

consigner() {
  local code="$1" duree="$2" detail="$3"
  install -d -m 0750 "$(dirname "$journal_taches")"
  printf '{"ts":"%s","task":"%s","exit_code":%d,"duration_ms":%d,"detail":"%s"}\n' \
    "$(horodatage)" "$(json_texte "$tache")" "$code" "$duree" "$(json_texte "$detail")" >> "$journal_taches"
}

# Jauges de la tâche pour le collecteur textfile (écriture par renommage), quand la supervision est réglée.
exposer_tache() {
  local code="$1" f tmp
  [ -n "$supervision" ] || return 0
  install -d -m 0755 "$supervision" || return 0
  f="$supervision/tache-$tache.prom"
  tmp="$f.$$.tmp"
  {
    echo "# HELP noortrace_tache_code Code de sortie de la derniere execution de la tache planifiee (CT-8 EX-8.6)."
    echo "# TYPE noortrace_tache_code gauge"
    echo "noortrace_tache_code{task=\"$tache\"} $code"
    echo "# HELP noortrace_tache_derniere_s Fin de la derniere execution de la tache planifiee, en secondes UNIX."
    echo "# TYPE noortrace_tache_derniere_s gauge"
    echo "noortrace_tache_derniere_s{task=\"$tache\"} $(date -u +%s)"
  } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f"
}

# relever <check> <commande…> : relecture hors du composant exposée par sonde.mjs releve (EX-10.9),
# qui rend le code de la relecture ; sans supervision réglée, ou en mode --relecture, la commande seule.
relever() {
  local check="$1"
  shift
  if [ -n "$supervision" ] && [ "$relecture" -eq 0 ]; then
    install -d -m 0755 "$supervision"
    node "$racine/scripts/deploiement/sonde.mjs" releve --check "$check" --sortie "$supervision/releve-$check.prom" -- "$@"
  else
    "$@"
  fi
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
  local variable="$1" check="${2:-}"
  if [ -z "${!variable:-}" ]; then
    echo "Erreur : $variable non réglée : aucun outil du dépôt pour $tache, la commande est celle du client" >&2
    return 3
  fi
  if [ -n "$check" ]; then relever "$check" bash -c "${!variable}"; else bash -c "${!variable}"; fi
}

# TP-4 : relecture de tout le registre des gels avec les identifiants du Lecteur, hors du démon
# (CT-2 EX-17.7 ; « worm gel liste », étape 8, EX-12.36 : la liste des gels relus n'est plus un
# réglage que tient l'administrateur), puis de chaque gel que NOORTRACE_TP4_GELS nomme encore
# (facultatif, « worm gel etat --gel »). Le code est le premier code non nul rencontré.
noortrace_ctl_lecteur() {
  dc run --rm --no-deps -T \
    -v "$NOORTRACE_TP4_IDENTIFIANTS:/run/noortrace-lecteur/identifiants:ro" \
    --entrypoint /usr/local/bin/noortrace-ctl enregistreur \
    worm gel "$@" --configuration /etc/noortrace/configuration.json \
    --identifiants '{"file":"/run/noortrace-lecteur/identifiants"}'
}
tp4_relire() {
  local g code=0
  noortrace_ctl_lecteur liste || code=$?
  for g in ${NOORTRACE_TP4_GELS:-}; do
    noortrace_ctl_lecteur etat --gel "$g" || { [ "$code" -ne 0 ] || code=$?; }
  done
  return $code
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
      # Relecture de tout le registre des gels avec les identifiants du Lecteur, hors du démon
      # (CT-2 EX-17.7), exposée par sonde.mjs releve --check registre_gels (EX-10.9).
      requis NOORTRACE_RACINE NOORTRACE_TP4_IDENTIFIANTS || return $?
      if [ "$relecture" -eq 1 ]; then tp4_relire; else relever registre_gels bash "${BASH_SOURCE[0]}" TP-4 --relecture; fi
      ;;
    TP-5) commande_client NOORTRACE_TP5_COMMANDE console ;;
    TP-6)
      # Fichiers tournés du journal d'exploitation (CT-8 EX-11.22, EX-11.23) : copie, puis relecture
      # de la série copiée exposée par sonde.mjs releve --check copie_exploitation (EX-10.9).
      requis NOORTRACE_RACINE NOORTRACE_INSTANCE || return $?
      local rep code=0
      rep="$(volume exploitation)" || return 2
      node "$racine/scripts/deploiement/archiver-journal-exploitation.mjs" \
        --journal "$rep/${NOORTRACE_OPS_LOG:-exploitation.ndjson}" --instance "$NOORTRACE_INSTANCE" \
        --vers "$exploitation/journal-exploitation" || code=$?
      relever copie_exploitation node "$racine/scripts/deploiement/archiver-journal-exploitation.mjs" \
        --verifier --instance "$NOORTRACE_INSTANCE" --vers "$exploitation/journal-exploitation" || code=$?
      return $code
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
if [ "$relecture" -eq 1 ]; then
  executer
  exit $?
fi
debut="$(ms)"
sortie_tache="$(executer 2>&1)"
code=$?
printf '%s\n' "$sortie_tache"
consigner "$code" "$(( $(ms) - debut ))" "$(printf '%s' "$sortie_tache" | tail -n 1 | cut -c1-500)"
exposer_tache "$code"
exit "$code"
