#!/usr/bin/env bash
# Préparation de l'hôte NOORTRACE (CT-8 §8.3, pas IC-2) sur le système de
# référence de CT-9 (EX-11.1) : Ubuntu 24.04 (noble), x86_64.
#
#   sudo bash deploiement/hote/preparer-hote.sh [--simulation] [--archive-node <fichier>] \
#     [--prefixe <répertoire>] [--utilisateur <nom>] [--stockage <point de montage>] \
#     [--declaration-cache <texte>] [--pv <répertoire du procès-verbal>]
#
# Pas, chacun contrôlé avant d'agir (un second passage ne change rien) :
#   systeme     Ubuntu 24.04 sur x86_64, sinon code 3 (aucune action).
#   paquets     docker.io, docker-compose-v2, chrony, curl, openssl,
#               ca-certificates, xz-utils, par apt-get depuis les sources
#               configurées de l'hôte (flux FL-31 de CT-8, ouvert pendant
#               l'installation, règle 6 d'EX-5.2) ; seuls les paquets absents
#               sont installés. Le script ne nomme aucun dépôt ni aucune
#               adresse : l'hôte garde les siens.
#   services    docker et chrony activés et démarrés (systemctl).
#   node        Node.js VERSION_NODE exactement (v22.23.4, la version livrée) :
#               présent (node --version), ou installé depuis l'archive
#               officielle node-v22.23.4-linux-x64.tar.xz, obtenue par
#               l'exploitant avec la note de version et déposée sur l'hôte
#               (--archive-node) : l'archive est d'abord copiée dans un
#               répertoire privé du superutilisateur (mktemp -d), la copie
#               est vérifiée (SHA-256 égal à SHA256_NODE, sinon refus) puis
#               extraite sous <prefixe>/lib/nodejs, liens node, npm et npx
#               sous <prefixe>/bin ; un Node.js 22 d'une autre version déjà
#               présent n'est pas « déjà fait » : l'écart est nommé et la
#               version livrée exigée (CT-8 IC-2). Ubuntu 24.04 ne
#               fournit que Node.js 18.
#   moteur      /etc/docker/daemon.json porte la rotation des journaux des
#               conteneurs (log-driver json-file, log-opts max-size 50m et
#               max-file 5 : CT-8 CO-8 n'admet pas logging dans les fichiers
#               Compose ; revue de sécurité de l'étape 8) : fichier absent, écrit
#               puis moteur relancé ; fichier présent avec ces réglages, déjà
#               fait ; fichier présent sans eux, échec qui nomme les clés à
#               ajouter (le script ne réécrit pas un réglage du client).
#   groupe      --utilisateur ajouté au groupe docker (droits équivalents à
#               ceux du superutilisateur, CT-8 IC-2) ; sans l'option, sudo
#               devant chaque commande docker.
#   stockage    --stockage : système de fichiers ext4, xfs ou btrfs, jamais
#               NFS ni SMB (CT-2 EX-12.2). Le montage reste l'acte du client.
#   verification  docker version, docker compose version, node --version,
#               chronyc tracking (statut de saut Normal) ; avec --pv, chaque
#               sortie dans <pv>/IC-2-*.txt, avec la liste des versions des
#               paquets et la déclaration du cache d'écriture (EX-6.4) ;
#               chaque fichier du procès-verbal est créé en exclusivité
#               (noclobber) après retrait d'un fichier du même nom : un lien
#               posé à sa place n'est jamais suivi (CT-8 IC-2).
#
# --simulation : n'agit pas, n'exige pas root, dit pour chaque pas « déjà
# fait » ou « à faire ». --os-release <fichier> remplace /etc/os-release et
# --daemon-json <fichier> remplace /etc/docker/daemon.json (essais seulement).
# Codes : 0 hôte prêt ; 1 un pas a échoué ; 2 usage (ou sans root hors
# simulation) ; 3 système non pris en charge ; 4 simulation : des pas restent
# à faire.

set -euo pipefail
export LC_ALL=C

# Même version que la base des images (node:22.23.4-bookworm-slim) et que
# le travail de version : une seule version de Node.js livrée.
readonly VERSION_NODE="v22.23.4"
readonly NOM_NODE="node-${VERSION_NODE}-linux-x64"
# SHA-256 de node-v22.23.4-linux-x64.tar.xz (liste SHASUMS256.txt de la
# version, signée par l'éditeur, version publiée le 2026-10-20, relevée et
# l'archive vérifiée le 2026-11-12).
readonly SHA256_NODE="1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce"
readonly PAQUETS=(docker.io docker-compose-v2 chrony curl openssl ca-certificates xz-utils)
readonly SERVICES=(docker chrony)

simulation=0
archive_node=""
prefixe="/usr/local"
utilisateur=""
stockage=""
declaration_cache=""
pv=""
os_release="/etc/os-release"
daemon_json="/etc/docker/daemon.json"
reste=0
# Rotation des journaux des conteneurs posée dans daemon.json (pas moteur).
readonly JOURNAUX_MOTEUR='{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  }
}'

usage() {
  echo "Usage : sudo bash deploiement/hote/preparer-hote.sh [--simulation] [--archive-node <fichier>] [--prefixe <répertoire>] [--utilisateur <nom>] [--stockage <point de montage>] [--declaration-cache <texte>] [--pv <répertoire>]" >&2
}

erreur_usage() {
  echo "Erreur : $1" >&2
  usage
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --simulation) simulation=1; shift ;;
    --archive-node|--prefixe|--utilisateur|--stockage|--declaration-cache|--pv|--os-release|--daemon-json)
      [ $# -ge 2 ] || erreur_usage "valeur manquante pour $1"
      case "$1" in
        --archive-node) archive_node="$2" ;;
        --prefixe) prefixe="$2" ;;
        --utilisateur) utilisateur="$2" ;;
        --stockage) stockage="$2" ;;
        --declaration-cache) declaration_cache="$2" ;;
        --pv) pv="$2" ;;
        --os-release) os_release="$2" ;;
        --daemon-json) daemon_json="$2" ;;
      esac
      shift 2 ;;
    *) erreur_usage "option inconnue : $1" ;;
  esac
done

[ -n "$stockage" ] || [ -z "$declaration_cache" ] || erreur_usage "--declaration-cache exige --stockage"
if [ "$simulation" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  erreur_usage "à exécuter avec sudo (ou --simulation)"
fi

dire() { printf 'IC-2 %-12s %s\n' "$1" "$2"; }
a_faire() { dire "$1" "à faire : $2"; reste=1; }
echec() { dire "$1" "échec : $2"; exit 1; }

# --- systeme ---------------------------------------------------------------
id_os=""; version_os=""
if [ -r "$os_release" ]; then
  id_os="$(sed -n 's/^ID=//p' "$os_release" | tr -d '"')"
  version_os="$(sed -n 's/^VERSION_ID=//p' "$os_release" | tr -d '"')"
fi
architecture="$(uname -m)"
if [ "$id_os" != "ubuntu" ] || [ "$version_os" != "24.04" ] || [ "$architecture" != "x86_64" ]; then
  dire systeme "non pris en charge : ${id_os:-?} ${version_os:-?} ${architecture} (système de référence : ubuntu 24.04 x86_64, CT-9 EX-11.1)"
  exit 3
fi
dire systeme "ubuntu ${version_os} ${architecture}"

# --- paquets ---------------------------------------------------------------
paquet_installe() {
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true)" = "installed" ]
}
manquants=()
for p in "${PAQUETS[@]}"; do
  paquet_installe "$p" || manquants+=("$p")
done
if [ ${#manquants[@]} -eq 0 ]; then
  dire paquets "déjà fait (${PAQUETS[*]})"
elif [ "$simulation" -eq 1 ]; then
  a_faire paquets "apt-get install ${manquants[*]}"
else
  DEBIAN_FRONTEND=noninteractive apt-get update -q || echec paquets "apt-get update (sources de l'hôte, flux FL-31)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${manquants[@]}" || echec paquets "apt-get install ${manquants[*]}"
  for p in "${manquants[@]}"; do paquet_installe "$p" || echec paquets "$p toujours absent après installation"; done
  dire paquets "fait (${manquants[*]})"
fi

# --- services --------------------------------------------------------------
for s in "${SERVICES[@]}"; do
  if systemctl is-enabled --quiet "$s" 2>/dev/null && systemctl is-active --quiet "$s" 2>/dev/null; then
    dire services "déjà fait ($s)"
  elif [ "$simulation" -eq 1 ]; then
    a_faire services "systemctl enable --now $s"
  else
    systemctl enable --now "$s" || echec services "systemctl enable --now $s"
    dire services "fait ($s)"
  fi
done

# --- node ------------------------------------------------------------------
version_node() {
  local n
  for n in "$prefixe/bin/node" "$(command -v node 2>/dev/null || true)"; do
    if [ -n "$n" ] && [ -x "$n" ]; then "$n" --version 2>/dev/null && return 0; fi
  done
  return 1
}
vn="$(version_node || true)"
# Écart nommé quand un autre Node.js 22 est présent : la version livrée est exigée (CT-8 IC-2).
ecart_node=""
case "$vn" in
  "$VERSION_NODE") ;;
  v22.*) ecart_node="Node.js $vn présent, version livrée ${VERSION_NODE} absente" ;;
  *) ecart_node="Node.js 22 absent (${vn:-aucun} ; version livrée ${VERSION_NODE})" ;;
esac
if [ -z "$ecart_node" ]; then
  dire node "déjà fait ($vn)"
elif [ -z "$archive_node" ]; then
  if [ "$simulation" -eq 1 ]; then
    a_faire node "$ecart_node : --archive-node ${NOM_NODE}.tar.xz"
  else
    echec node "$ecart_node ; donner --archive-node ${NOM_NODE}.tar.xz (SHA-256 ${SHA256_NODE})"
  fi
else
  [ -f "$archive_node" ] || echec node "$archive_node introuvable"
  # Copie privée avant tout contrôle : ce qui est vérifié est ce qui est extrait (pas de relecture du chemin donné).
  copie_node="$(mktemp -d)" || echec node "répertoire temporaire impossible"
  trap 'rm -rf "$copie_node"' EXIT
  cp -- "$archive_node" "$copie_node/${NOM_NODE}.tar.xz" || echec node "copie de $archive_node impossible"
  somme="$(sha256sum "$copie_node/${NOM_NODE}.tar.xz" | cut -d' ' -f1)"
  [ "$somme" = "$SHA256_NODE" ] || echec node "SHA-256 de $archive_node : $somme au lieu de $SHA256_NODE (archive refusée, rien n'est installé)"
  if [ "$simulation" -eq 1 ]; then
    a_faire node "$ecart_node : extraire ${NOM_NODE} sous $prefixe/lib/nodejs"
  else
    install -d -m 0755 "$prefixe/lib/nodejs" "$prefixe/bin"
    if [ ! -x "$prefixe/lib/nodejs/${NOM_NODE}/bin/node" ]; then
      tar -xJf "$copie_node/${NOM_NODE}.tar.xz" -C "$prefixe/lib/nodejs" --no-same-owner || echec node "extraction de $archive_node"
    fi
    for b in node npm npx; do
      ln -sfn "$prefixe/lib/nodejs/${NOM_NODE}/bin/$b" "$prefixe/bin/$b"
    done
    vn="$("$prefixe/bin/node" --version)" || echec node "node installé ne démarre pas"
    [ "$vn" = "$VERSION_NODE" ] && dire node "fait ($vn)" || echec node "version $vn après installation (${VERSION_NODE} attendue)"
  fi
  rm -rf "$copie_node"
  trap - EXIT
fi

# --- moteur ----------------------------------------------------------------
# Rotation des journaux des conteneurs (CO-8 n'admet pas `logging` dans les fichiers Compose).
journaux_moteur_poses() {
  [ -r "$daemon_json" ] || return 1
  tr -d ' \n\t' < "$daemon_json" | grep -q '"log-driver":"json-file"' && tr -d ' \n\t' < "$daemon_json" | grep -q '"max-size":"' && tr -d ' \n\t' < "$daemon_json" | grep -q '"max-file":"'
}
if journaux_moteur_poses; then
  dire moteur "déjà fait (rotation des journaux dans $daemon_json)"
elif [ -e "$daemon_json" ] && [ -n "$(tr -d ' \n\t{}' < "$daemon_json")" ]; then
  echec moteur "$daemon_json existe sans rotation des journaux : y ajouter \"log-driver\": \"json-file\" et \"log-opts\": {\"max-size\": \"50m\", \"max-file\": \"5\"} (le script ne réécrit pas un réglage existant)"
elif [ "$simulation" -eq 1 ]; then
  a_faire moteur "écrire la rotation des journaux dans $daemon_json puis relancer docker"
else
  install -d -m 0755 "$(dirname "$daemon_json")"
  printf '%s\n' "$JOURNAUX_MOTEUR" > "$daemon_json.nouveau" && chmod 0644 "$daemon_json.nouveau" && mv -f "$daemon_json.nouveau" "$daemon_json" || echec moteur "écriture de $daemon_json"
  systemctl restart docker || echec moteur "systemctl restart docker après l'écriture de $daemon_json"
  dire moteur "fait (rotation des journaux dans $daemon_json, moteur relancé)"
fi

# --- groupe ----------------------------------------------------------------
if [ -n "$utilisateur" ]; then
  id "$utilisateur" >/dev/null 2>&1 || echec groupe "utilisateur $utilisateur inconnu"
  if id -nG "$utilisateur" | tr ' ' '\n' | grep -qx docker; then
    dire groupe "déjà fait ($utilisateur dans docker)"
  elif [ "$simulation" -eq 1 ]; then
    a_faire groupe "usermod -aG docker $utilisateur"
  else
    usermod -aG docker "$utilisateur" || echec groupe "usermod -aG docker $utilisateur"
    dire groupe "fait ($utilisateur dans docker ; effet à la prochaine session)"
  fi
fi

# --- stockage --------------------------------------------------------------
if [ -n "$stockage" ]; then
  [ -d "$stockage" ] || echec stockage "$stockage n'est pas un répertoire"
  type_fs="$(findmnt -n -o FSTYPE --target "$stockage" 2>/dev/null || true)"
  case "$type_fs" in
    ext4|xfs|btrfs) dire stockage "$stockage sur $type_fs" ;;
    *) echec stockage "$stockage sur ${type_fs:-?} : ext4, xfs ou btrfs exigé, jamais NFS ni SMB (CT-2 EX-12.2)" ;;
  esac
fi

if [ "$simulation" -eq 1 ]; then
  if [ "$reste" -eq 1 ]; then dire bilan "simulation : des pas restent à faire"; exit 4; fi
  dire bilan "simulation : hôte prêt"
  exit 0
fi

# --- verification ----------------------------------------------------------
# Écriture d'un fichier du procès-verbal : fichier (ou lien) du même nom retiré, puis création en
# exclusivité (noclobber, O_EXCL) : un lien posé dans le répertoire n'est jamais suivi.
ecrire_pv() {
  local f="$pv/IC-2-$1.txt"; shift
  [ -d "$pv" ] && [ ! -L "$pv" ] || echec verification "$pv n'est pas un répertoire"
  rm -f -- "$f"
  ( set -o noclobber; "$@" > "$f" 2>&1 )
}
consigner() {
  local nom="$1"; shift
  if [ -n "$pv" ]; then
    ecrire_pv "$nom" "$@" || echec verification "$* (voir $pv/IC-2-$nom.txt)"
  else
    "$@" >/dev/null 2>&1 || echec verification "$*"
  fi
}
if [ -n "$pv" ]; then
  [ -d "$pv" ] || echec verification "$pv n'existe pas (IC-1 l'ouvre)"
fi
consigner docker-version docker version
consigner docker-compose-version docker compose version
node_bin="$prefixe/bin/node"; [ -x "$node_bin" ] || node_bin="$(command -v node)"
consigner node-version "$node_bin" --version
saut="$(chronyc -c tracking 2>/dev/null | awk -F, '{print $NF}' || true)"
if [ "$saut" != "Normal" ]; then
  chronyc waitsync 30 >/dev/null 2>&1 || true
  saut="$(chronyc -c tracking 2>/dev/null | awk -F, '{print $NF}' || true)"
fi
[ "$saut" = "Normal" ] || echec verification "chronyc tracking : statut de saut ${saut:-illisible} (Normal attendu, R9-F41)"
consigner chronyc-tracking chronyc tracking
if [ -n "$pv" ]; then
  ecrire_pv paquets dpkg-query -W -f='${binary:Package} ${Version}\n' "${PAQUETS[@]}" || echec verification "liste des paquets (voir $pv/IC-2-paquets.txt)"
  if [ -n "$stockage" ]; then
    ecrire_pv stockage printf '%s\n' "stockage : $stockage ($type_fs)" "cache d'écriture : ${declaration_cache:-NON DÉCLARÉ (EX-6.4 : déclaration et sa source à consigner)}" || echec verification "déclaration du stockage (voir $pv/IC-2-stockage.txt)"
  fi
fi
dire bilan "hôte prêt"
exit 0
