#!/usr/bin/env bash
# Pose des tâches planifiées de NOORTRACE (CT-8 EX-8.6, pas IC-16) avec le
# minuteur du système (systemd) : une unité de service gabarit
# noortrace-tache@.service et un minuteur par tâche retenue.
#
#   sudo bash deploiement/taches/poser-taches.sh --racine <répertoire de l'archive> \
#     [--taches TP-1,TP-2,…,SAUVEGARDE] [--sortie <répertoire des unités>] \
#     [--environnement <fichier>] [--supervision [<répertoire du collecteur>]] \
#     [--sans-activation] [--premiere-execution]
#
# --racine : répertoire d'extraction de l'archive de déploiement (contient
#   deploiement/ et scripts/), chemin absolu ; il remplace @RACINE@ dans les
#   gabarits de deploiement/taches/systemd/. Les minuteurs y exécutent des
#   scripts sous l'identité du superutilisateur : chaque composant du chemin,
#   executer-tache.sh, superviser.sh et les outils de scripts/deploiement/
#   qu'ils lancent doivent appartenir au superutilisateur (à l'appelant quand
#   il n'est pas le superutilisateur : rien ne peut alors être activé) et
#   n'être inscriptibles ni par le groupe ni par les autres (un répertoire à
#   bit collant, comme /tmp, est admis) ; sinon code 2 (CT-8 IC-16).
# --supervision : pose aussi noortrace-extracteur.service et
#   noortrace-sonde.service (extracteur de 10.3 et sonde d'EX-10.7, sous le
#   compte noortrace-supervision, créé à l'activation s'il manque, EX-10.3),
#   qui écrivent dans le répertoire du collecteur textfile de l'exportateur
#   de nœud (défaut /var/lib/noortrace-supervision, créé à l'activation,
#   0755, propriété de ce compte) ; ce répertoire remplace @SUPERVISION@ dans
#   les gabarits et NOORTRACE_SUPERVISION dans les réglages, avec ou sans
#   --supervision (les tâches y écrivent leurs jauges, EX-10.9).
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
supervision=0
repertoire_supervision="/var/lib/noortrace-supervision"
compte_supervision="noortrace-supervision"

usage() {
  echo "Usage : sudo bash deploiement/taches/poser-taches.sh --racine <répertoire de l'archive> [--taches TP-1,…,SAUVEGARDE] [--sortie <répertoire>] [--environnement <fichier>] [--supervision [<répertoire du collecteur>]] [--sans-activation] [--premiere-execution]" >&2
}
erreur_usage() { echo "Erreur : $1" >&2; usage; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sans-activation) activer=0; shift ;;
    --premiere-execution) premiere=1; shift ;;
    --supervision)
      supervision=1
      if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then repertoire_supervision="$2"; shift 2; else shift; fi ;;
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
case "$repertoire_supervision" in /*) ;; *) erreur_usage "--supervision : chemin absolu attendu" ;; esac
case "$repertoire_supervision" in *[!A-Za-z0-9._/-]*) erreur_usage "--supervision : caractères admis [A-Za-z0-9._/-]" ;; esac
repertoire_supervision="${repertoire_supervision%/}"

# Propriété de ce que le superutilisateur exécutera (CT-8 IC-16) : chaque composant de la racine
# et chaque script lancé par les unités appartient au superutilisateur et n'est inscriptible ni par
# le groupe ni par les autres ; un répertoire à bit collant est admis (/tmp : nul autre que le
# propriétaire n'y renomme ni ne supprime une entrée). Lancé hors superutilisateur (essais, unités
# écrites sous --sortie sans activation), le compte courant est admis en plus : les composants
# communs du chemin (/, /home, /tmp) restent au superutilisateur.
compte_attendu=0
[ "$(id -u)" -eq 0 ] || compte_attendu="$(id -u)"
controler_propriete() {
  local chemin="$1" uid mode
  read -r uid mode < <(stat -L -c '%u %a' -- "$chemin" 2>/dev/null) || erreur_usage "--racine : $chemin illisible"
  [ "$uid" = 0 ] || [ "$uid" = "$compte_attendu" ] || erreur_usage "--racine : $chemin appartient au compte $uid, non au compte 0$([ "$compte_attendu" = 0 ] || echo " ni au compte $compte_attendu") : les minuteurs y exécutent des scripts en superutilisateur"
  local droits=$(( 8#$mode ))
  if [ $(( droits & 8#22 )) -ne 0 ]; then
    [ -d "$chemin" ] && [ $(( droits & 8#1000 )) -ne 0 ] || erreur_usage "--racine : $chemin inscriptible par le groupe ou les autres (mode $mode)"
  fi
}
p="$racine"
while :; do
  controler_propriete "$p"
  [ "$p" != "/" ] || break
  p="$(dirname "$p")"
done
for f in deploiement deploiement/taches deploiement/taches/executer-tache.sh deploiement/taches/superviser.sh scripts scripts/deploiement \
  scripts/deploiement/sonde.mjs scripts/deploiement/extraire-journaux.mjs scripts/deploiement/archiver-journal-exploitation.mjs \
  scripts/deploiement/sauvegarde.mjs scripts/deploiement/controle-prealable.mjs; do
  [ -e "$racine/$f" ] || continue
  controler_propriete "$racine/$f"
done

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
substituer() { sed -e "s|@RACINE@|$racine|g" -e "s|@SUPERVISION@|$repertoire_supervision|g" "$1"; }
ecrire() {
  substituer "$ici/systemd/$1" > "$sortie/$1.nouveau"
  chmod 0644 "$sortie/$1.nouveau"
  mv -f "$sortie/$1.nouveau" "$sortie/$1"
  echo "IC-16 unité $sortie/$1"
}
ecrire "noortrace-tache@.service"
for t in "${retenues[@]}"; do ecrire "$(minuteur "$t")"; done
services_supervision=(noortrace-extracteur.service noortrace-sonde.service)
if [ "$supervision" -eq 1 ]; then
  for s in "${services_supervision[@]}"; do ecrire "$s"; done
fi

if [ ! -e "$environnement" ]; then
  install -d -m 0750 "$(dirname "$environnement")"
  substituer "$ici/taches.env.modele" > "$environnement"
  chmod 0600 "$environnement"
  echo "IC-16 réglages $environnement (à compléter)"
else
  echo "IC-16 réglages $environnement (existant, gardé)"
fi

[ "$activer" -eq 1 ] || { echo "IC-16 unités écrites, non activées"; exit 0; }
if [ "$supervision" -eq 1 ]; then
  # Compte de la supervision (EX-10.3 : identité distincte) et répertoire du collecteur textfile.
  if ! getent passwd "$compte_supervision" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$compte_supervision"
    echo "IC-16 compte $compte_supervision créé"
  fi
  install -d -m 0755 -o "$compte_supervision" -g "$compte_supervision" "$repertoire_supervision"
fi
systemctl daemon-reload
for t in "${retenues[@]}"; do systemctl enable --now "$(minuteur "$t")" >/dev/null; echo "IC-16 minuteur $(minuteur "$t") actif"; done
if [ "$supervision" -eq 1 ]; then
  for s in "${services_supervision[@]}"; do systemctl enable --now "$s" >/dev/null; echo "IC-16 service $s actif"; done
fi

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
