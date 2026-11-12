#!/usr/bin/env bash
# Pose des tâches planifiées de NOORTRACE (CT-8 EX-8.6, pas IC-16) avec le
# minuteur du système (systemd) : une unité de service gabarit
# noortrace-tache@.service et un minuteur par tâche retenue.
#
#   sudo bash deploiement/taches/poser-taches.sh --racine <répertoire de l'archive> \
#     [--taches TP-1,TP-2,…,SAUVEGARDE] [--sortie <répertoire des unités>] \
#     [--environnement <fichier>] [--sans-activation] [--premiere-execution]
#
# --racine : répertoire d'extraction de l'archive de déploiement (contient
#   deploiement/ et scripts/), chemin absolu ; il remplace @RACINE@ dans les
#   gabarits de deploiement/taches/systemd/.
# --taches : tâches retenues (défaut : celles d'EX-8.6 qui valent « toujours »
#   ou « toujours en production », TP-2, TP-6, TP-7, TP-8, et SAUVEGARDE ;
#   ajouter TP-1 pour un support dont le mode conformité n'est pas validé,
#   TP-3 pour headers_source fichier, TP-4 avec un support WORM, TP-5 avec la
#   console).
# --sortie : répertoire des unités (défaut /etc/systemd/system) ;
#   --environnement : fichier des réglages (défaut /etc/noortrace/taches.env),
#   copié du modèle taches.env.modele s'il n'existe pas, jamais remplacé.
# Sans --sans-activation : systemctl daemon-reload, puis enable --now de
# chaque minuteur retenu. --premiere-execution : lance chaque tâche retenue une
# fois (systemctl start, attente de sa fin) : IC-16 exige une première
# exécution réussie de chacune, consignée au journal des tâches.
# Un second passage réécrit les mêmes unités et ne change rien d'autre.
# Codes : 0 posé (et premières exécutions réussies) ; 1 une première
# exécution a échoué ; 2 usage.

set -euo pipefail
export LC_ALL=C

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
racine=""
taches="TP-2,TP-6,TP-7,TP-8,SAUVEGARDE"
sortie="/etc/systemd/system"
environnement="/etc/noortrace/taches.env"
activer=1
premiere=0

usage() {
  echo "Usage : sudo bash deploiement/taches/poser-taches.sh --racine <répertoire de l'archive> [--taches TP-1,…,SAUVEGARDE] [--sortie <répertoire>] [--environnement <fichier>] [--sans-activation] [--premiere-execution]" >&2
}
erreur_usage() { echo "Erreur : $1" >&2; usage; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sans-activation) activer=0; shift ;;
    --premiere-execution) premiere=1; shift ;;
    --racine|--taches|--sortie|--environnement)
      [ $# -ge 2 ] || erreur_usage "valeur manquante pour $1"
      case "$1" in
        --racine) racine="$2" ;;
        --taches) taches="$2" ;;
        --sortie) sortie="$2" ;;
        --environnement) environnement="$2" ;;
      esac
      shift 2 ;;
    *) erreur_usage "option inconnue : $1" ;;
  esac
done

[ -n "$racine" ] || erreur_usage "option --racine requise"
case "$racine" in /*) ;; *) erreur_usage "--racine : chemin absolu attendu" ;; esac
racine="${racine%/}"
[ -f "$racine/deploiement/taches/executer-tache.sh" ] || erreur_usage "--racine : $racine/deploiement/taches/executer-tache.sh absent"
case "$racine" in *[!A-Za-z0-9._/-]*) erreur_usage "--racine : caractères admis [A-Za-z0-9._/-]" ;; esac
[ "$premiere" -eq 0 ] || [ "$activer" -eq 1 ] || erreur_usage "--premiere-execution exige l'activation"

minuteur() {
  case "$1" in
    TP-[1-8]) echo "noortrace-tp${1#TP-}.timer" ;;
    SAUVEGARDE) echo "noortrace-sauvegarde.timer" ;;
    *) return 1 ;;
  esac
}

retenues=()
IFS=',' read -r -a liste <<< "$taches"
for t in "${liste[@]}"; do
  m="$(minuteur "$t")" || erreur_usage "--taches : $t inconnue (TP-1 à TP-8, SAUVEGARDE)"
  for r in "${retenues[@]}"; do [ "$r" != "$t" ] || erreur_usage "--taches : $t en double"; done
  retenues+=("$t")
done

install -d -m 0755 "$sortie"
ecrire() {
  sed "s|@RACINE@|$racine|g" "$ici/systemd/$1" > "$sortie/$1.nouveau"
  chmod 0644 "$sortie/$1.nouveau"
  mv -f "$sortie/$1.nouveau" "$sortie/$1"
  echo "IC-16 unité $sortie/$1"
}
ecrire "noortrace-tache@.service"
for t in "${retenues[@]}"; do ecrire "$(minuteur "$t")"; done

if [ ! -e "$environnement" ]; then
  install -d -m 0750 "$(dirname "$environnement")"
  sed "s|@RACINE@|$racine|g" "$ici/taches.env.modele" > "$environnement"
  chmod 0600 "$environnement"
  echo "IC-16 réglages $environnement (à compléter)"
else
  echo "IC-16 réglages $environnement (existant, gardé)"
fi

[ "$activer" -eq 1 ] || { echo "IC-16 unités écrites, non activées"; exit 0; }
systemctl daemon-reload
for t in "${retenues[@]}"; do systemctl enable --now "$(minuteur "$t")" >/dev/null; echo "IC-16 minuteur $(minuteur "$t") actif"; done

[ "$premiere" -eq 1 ] || exit 0
code=0
for t in "${retenues[@]}"; do
  if systemctl start "noortrace-tache@$t.service"; then
    echo "IC-16 première exécution de $t : réussie"
  else
    echo "IC-16 première exécution de $t : échec (journalctl -u noortrace-tache@$t.service ; journal des tâches)"
    code=1
  fi
done
exit "$code"
