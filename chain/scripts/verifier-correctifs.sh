#!/usr/bin/env bash
# Vérifie les correctifs NOORTRACE déposés dans chain/patches/ contre le fichier
# suivi chain/patches/EMPREINTES avant toute application (CT-4 EX-10.1 c, d ;
# revue de sécurité interne). Appelé par chain/scripts/build-noorcore.sh
# et par chain/docker/Dockerfile ; utilisable seul :
#
#   bash chain/scripts/verifier-correctifs.sh <répertoire des correctifs> [<fichier EMPREINTES>]
#
# EMPREINTES : une ligne par correctif attendu, au format de sha256sum
# (« <sha256 en hexadécimal>  <nom>.patch »), lignes vides et commentaires « # »
# ignorés ; le nom est un nom de fichier sans répertoire. Le fichier dit quels
# correctifs une construction applique, et avec quels octets ; il ne porte
# jamais leur contenu (CT-4 EX-10.1 c).
#
# Codes de retour :
#   0  chaque correctif listé est présent avec l'empreinte attendue, et aucun
#      fichier *.patch non listé n'est présent ;
#   0  avec NOORTRACE_SANS_CORRECTIF=1 et aucun fichier *.patch présent :
#      construction sans correctif admise, sur demande explicite seulement
#      (le binaire n'a pas noor_getCommitCertificate : étiqueter l'image
#      autrement que l'image livrée, chain/docker/README.md) ;
#   1  empreinte différente, correctif listé absent, fichier *.patch non listé,
#      ligne d'EMPREINTES mal formée ;
#   2  arguments ou fichier EMPREINTES illisibles ;
#   3  aucun correctif présent alors qu'EMPREINTES en attend, sans
#      NOORTRACE_SANS_CORRECTIF=1 : rien ne doit être construit sous
#      l'étiquette de l'image livrée.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "verifier-correctifs: usage : verifier-correctifs.sh <répertoire des correctifs> [<fichier EMPREINTES>]" >&2
  exit 2
fi
dir="$1"
empreintes="${2:-$dir/EMPREINTES}"
if [[ ! -d "$dir" ]]; then
  echo "verifier-correctifs: répertoire des correctifs introuvable : $dir" >&2
  exit 2
fi
if [[ ! -r "$empreintes" ]]; then
  echo "verifier-correctifs: fichier des empreintes illisible : $empreintes" >&2
  exit 2
fi
# Chemin absolu : la vérification des empreintes se fait depuis le répertoire des correctifs.
empreintes="$(cd "$(dirname "$empreintes")" && pwd)/$(basename "$empreintes")"

# Lignes utiles d'EMPREINTES : « <64 chiffres hexadécimaux>  <nom>.patch », nom sans « / ».
attendus=()
while IFS= read -r ligne || [[ -n "$ligne" ]]; do
  [[ -z "${ligne//[[:space:]]/}" || "$ligne" == \#* ]] && continue
  if [[ ! "$ligne" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]?\*?([^/[:space:]]+\.patch)$ ]]; then
    echo "verifier-correctifs: ligne mal formée dans $empreintes : $ligne" >&2
    exit 1
  fi
  attendus+=("${BASH_REMATCH[1]}")
done < "$empreintes"

# Fichiers *.patch présents.
presents=()
shopt -s nullglob
for p in "$dir"/*.patch; do presents+=("$(basename "$p")"); done
shopt -u nullglob

if [[ ${#presents[@]} -eq 0 ]]; then
  if [[ ${#attendus[@]} -eq 0 ]]; then
    echo "verifier-correctifs: aucun correctif attendu ni présent"
    exit 0
  fi
  if [[ "${NOORTRACE_SANS_CORRECTIF:-0}" == "1" ]]; then
    echo "verifier-correctifs: AVERTISSEMENT : construction sans correctif demandée (NOORTRACE_SANS_CORRECTIF=1) alors qu'EMPREINTES attend : ${attendus[*]} ; le binaire n'aura pas noor_getCommitCertificate : ne pas l'étiqueter comme l'image livrée" >&2
    exit 0
  fi
  echo "verifier-correctifs: aucun correctif dans $dir alors que $empreintes attend : ${attendus[*]} ; déposer les correctifs (chain/patches/LISEZMOI.md), ou NOORTRACE_SANS_CORRECTIF=1 pour une construction sans correctif sous une autre étiquette" >&2
  exit 3
fi

code=0
# Un fichier présent que la liste ne nomme pas : refus (un correctif inconnu changerait le binaire sous la même étiquette).
for p in "${presents[@]}"; do
  liste_=0
  for a in "${attendus[@]}"; do [[ "$a" == "$p" ]] && liste_=1; done
  if [[ $liste_ -eq 0 ]]; then
    echo "verifier-correctifs: $p présent dans $dir mais absent de $empreintes : refus" >&2
    code=1
  fi
done
# Un correctif listé mais absent : refus (le binaire serait incomplet sous la même étiquette).
for a in "${attendus[@]}"; do
  if [[ ! -f "$dir/$a" ]]; then
    echo "verifier-correctifs: $a attendu par $empreintes mais absent de $dir : refus" >&2
    code=1
  fi
done
[[ $code -ne 0 ]] && exit "$code"

# Empreintes : sha256sum --strict -c sur les lignes utiles, depuis le répertoire des correctifs.
if ! (cd "$dir" && grep -Ev '^[[:space:]]*(#|$)' "$empreintes" | sha256sum --strict -c -) ; then
  echo "verifier-correctifs: au moins une empreinte diffère de $empreintes : refus (CT-4 EX-10.1 d)" >&2
  exit 1
fi
echo "verifier-correctifs: ${#attendus[@]} correctif(s) vérifié(s) contre $empreintes"
exit 0
