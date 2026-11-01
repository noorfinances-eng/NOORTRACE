#!/usr/bin/env bash
# Confrontation des paquets réviseurs de spec/vecteurs/ct-8/paquets/ par GNU
# tar, sha256sum (GNU coreutils) et jq (CT-8, annexe A.15, EX-A.32 à EX-A.35).
# N'emploie aucun code du dépôt et n'ouvre aucune connexion.
#
# Pour chaque archive (ordre des octets du nom) :
#   - SHA-256 de l'archive par sha256sum, comparé à archive_sha256 de cas.json ;
#   - liste par tar --list --verbose --numeric-owner --full-time ;
#   - extraction par tar -xf dans un répertoire neuf et vide (jamais -P ni -h),
#     code de retour et messages ;
#   - liens extraits, entrées apparues hors de la destination ;
#   - SHA-256 de chaque fichier déclaré par le manifeste extrait
#     (sha256sum --strict -c), fichiers extraits absents du manifeste, membres
#     listés comparés au manifeste (nom, taille, type) ;
#   - résultat comparé à l'attendu de CT-8 (cas.json, cas sans option qui
#     porte sur l'archive) : un paquet intact doit être lu sans écart ; un
#     écart au manifeste (PR-8) doit être trouvé par sha256sum ou par la
#     comparaison au manifeste ; un paquet que CT-8 refuse par une autre règle
#     (PR-4, PR-5, PR-6) est concordant si tar refuse l'extraction, et sinon
#     consigné comme limite de l'outil.
# Enfin, valide.tar est reconstruit par la recette d'EX-13.15 et comparé par
# cmp. Code 0 sans discordance, 1 avec au moins une discordance, 2 en cas
# d'usage incorrect ou d'outil absent.
#
#   bash confronter_gnutar.sh <répertoire des paquets> \
#       <répertoire de travail vide>
set -u
export LC_ALL=C TZ=UTC

if [ $# -ne 2 ]; then
  echo "usage : bash confronter_gnutar.sh <répertoire des paquets> <répertoire de travail vide>" >&2
  exit 2
fi
for outil in tar sha256sum jq cmp find sort awk date; do
  command -v "$outil" > /dev/null || { echo "outil absent : $outil" >&2; exit 2; }
done
tar --version | head -1 | grep -q '(GNU tar)' || { echo "tar n'est pas GNU tar" >&2; exit 2; }
PAQUETS=$(cd "$1" && pwd) || exit 2
TRAVAIL=$(cd "$2" && pwd) || exit 2
CAS="$PAQUETS/cas.json"
[ -f "$CAS" ] || { echo "cas.json absent du répertoire des paquets" >&2; exit 2; }
[ -z "$(ls -A "$TRAVAIL")" ] || { echo "répertoire de travail non vide" >&2; exit 2; }
mkdir "$TRAVAIL/extraits" "$TRAVAIL/aux" || exit 2
AUX="$TRAVAIL/aux"

# Remplace, sans expression rationnelle, les chemins locaux par <travail> et
# <paquets> : aucune sortie publiée ne porte de chemin local.
masquer() {
  awk -v t="$TRAVAIL" -v p="$PAQUETS" '{
    while ((i = index($0, t)) > 0) $0 = substr($0, 1, i - 1) "<travail>" substr($0, i + length(t));
    while ((i = index($0, p)) > 0) $0 = substr($0, 1, i - 1) "<paquets>" substr($0, i + length(p));
    print
  }'
}

# Imprime « titre : aucun » (ou le troisième argument) pour une liste vide,
# sinon « titre : n » puis chaque élément précédé de deux espaces.
liste() {
  local titre=$1 fichier=$2 aucun=${3:-aucun} n
  n=$(grep -c '' "$fichier")
  if [ "$n" -eq 0 ]; then echo "$titre : $aucun"; else echo "$titre : $n"; sed 's/^/  /' "$fichier"; fi
}

# Entrées du répertoire de travail qui ne sont ni aux/, ni extraits/, ni
# extraits/<archive>/, ni sous extraits/<archive>/dest/ (trois niveaux
# au-dessus de chaque destination sont ainsi surveillés).
hors_destination() {
  (cd "$TRAVAIL" && find . -mindepth 1 -maxdepth 3 -print | sort) | while IFS= read -r p; do
    case "$p" in
      ./aux | ./aux/* | ./extraits | ./extraits/*/dest) ;;
      ./extraits/*/*) echo "${p#./}" ;;
      ./extraits/*) if [ -d "$TRAVAIL/$p" ] && [ -f "$PAQUETS/${p#./extraits/}.tar" ]; then :; else echo "${p#./}"; fi ;;
      *) echo "${p#./}" ;;
    esac
  done
}

echo "# Confrontation des paquets réviseurs de CT-8 par $(tar --version | head -1), $(sha256sum --version | head -1), $(jq --version)"
echo "# Archives : $(cd "$PAQUETS" && find . -maxdepth 1 -type f -name '*.tar' | wc -l) ; cas.json : $(jq '.cases | length' "$CAS") cas"
archives=0
concordes=0
limites=0
discordances=0

for archive in $(cd "$PAQUETS" && find . -maxdepth 1 -type f -name '*.tar' -printf '%f\n' | sort); do
  nom=${archive%.tar}
  archives=$((archives + 1))
  sha_ok=1
  echo
  echo "== $archive"
  # Attendu de CT-8 : le cas sans option qui porte sur cette archive.
  base=$(jq -c --arg a "$archive" '[.cases[] | select(.archive == $a and .options.expected_sha256 == null and .options.anchors == null)] | first' "$CAS")
  if [ "$base" = "null" ]; then
    echo "attendu : aucun cas sans option dans cas.json : DISCORDANCE"
    discordances=$((discordances + 1))
    continue
  fi
  cas_nom=$(jq -r '.name' <<< "$base")
  attendu_sha=$(jq -r '.archive_sha256 | ltrimstr("0x")' <<< "$base")
  statut=$(jq -r '.expected.package_status' <<< "$base")
  regle=$(jq -r '[.expected.checks[] | select(.status == "echoue") | .id] | join(",")' <<< "$base")
  calcule=$(sha256sum "$PAQUETS/$archive" | cut -d' ' -f1)
  if [ "$calcule" = "$attendu_sha" ]; then
    echo "sha256sum : $calcule ; cas.json : concorde"
  else
    echo "sha256sum : $calcule ; cas.json : $attendu_sha : DISCORDANCE"
    sha_ok=0
  fi
  if [ "$statut" = "intact" ]; then
    echo "attendu (cas.json, cas $cas_nom) : paquet intact"
  else
    echo "attendu (cas.json, cas $cas_nom) : paquet $statut, $regle en échec"
  fi

  # Liste.
  tar --list --verbose --numeric-owner --full-time -f "$PAQUETS/$archive" > "$AUX/$nom.liste" 2> "$AUX/$nom.liste.err"
  code_liste=$?
  echo "-- liste (tar --list --verbose --numeric-owner --full-time) : code $code_liste, $(grep -c '' "$AUX/$nom.liste") membres"
  masquer < "$AUX/$nom.liste"
  masquer < "$AUX/$nom.liste.err" | sed 's/^/message : /'

  # Extraction dans un répertoire neuf et vide.
  mkdir -p "$TRAVAIL/extraits/$nom/dest"
  dest="$TRAVAIL/extraits/$nom/dest"
  tar -xf "$PAQUETS/$archive" -C "$dest" 2> "$AUX/$nom.err"
  code=$?
  echo "-- extraction (tar -xf, répertoire neuf et vide) : code $code"
  masquer < "$AUX/$nom.err" | sed 's/^/message : /'
  (cd "$dest" && find . -type l -printf '%P -> %l\n' | sort) > "$AUX/$nom.liens"
  liste "-- liens extraits" "$AUX/$nom.liens"
  hors_destination > "$AUX/$nom.hors"
  liste "-- entrées hors de la destination" "$AUX/$nom.hors" aucune

  ecarts=0
  m="$dest/paquet-reviseur/MANIFESTE.json"
  if [ -f "$m" ] && [ ! -L "$m" ] && jq -e '(.files | type) == "array"' "$m" > /dev/null 2>&1; then
    echo "-- manifeste extrait : $(jq '.files | length' "$m") fichiers déclarés"
    jq -r '.files[] | (.sha256 | ltrimstr("0x")) + "  paquet-reviseur/" + .path' "$m" > "$AUX/$nom.sums"
    (cd "$dest" && sha256sum --strict -c "$AUX/$nom.sums" > "$AUX/$nom.sums.out" 2> "$AUX/$nom.sums.err")
    code_sums=$?
    grep -v ': OK$' "$AUX/$nom.sums.out" | sed 's/: FAILED.*$//' | sort > "$AUX/$nom.echecs"
    echo "-- sha256sum --strict -c contre le manifeste : code $code_sums"
    sed 's/^/en échec : /' "$AUX/$nom.echecs"
    masquer < "$AUX/$nom.sums.err" | sed 's/^/message : /'
    ecarts=$((ecarts + $(grep -c '' "$AUX/$nom.echecs")))
    jq -r '.files[] | "paquet-reviseur/" + .path' "$m" | sort > "$AUX/$nom.declares"
    (cd "$dest" && find paquet-reviseur -type f ! -path paquet-reviseur/MANIFESTE.json | sort) > "$AUX/$nom.fichiers"
    comm -23 "$AUX/$nom.fichiers" "$AUX/$nom.declares" > "$AUX/$nom.en-trop"
    liste "-- fichiers extraits absents du manifeste" "$AUX/$nom.en-trop"
    ecarts=$((ecarts + $(grep -c '' "$AUX/$nom.en-trop") + $(grep -c '' "$AUX/$nom.liens")))
    # Membres listés contre le manifeste : nom répété, type autre que
    # fichier ordinaire, membre non déclaré, déclaré non listé, taille.
    jq -r '.files[] | "paquet-reviseur/" + .path + "\t" + (.size | tostring)' "$m" > "$AUX/$nom.tailles"
    awk -F '\t' -v liste="$AUX/$nom.liste" '
      FNR == NR { taille[$1] = $2; next }
      END {
        while ((getline l < liste) > 0) {
          if (!match(l, /^[^ ]+ [0-9]+\/[0-9]+ +[0-9]+ [0-9-]+ [0-9:]+ /)) { print "ligne illisible : " l; continue }
          type = substr(l, 1, 1); split(substr(l, 1, RLENGTH), c, / +/); n = substr(l, RLENGTH + 1)
          sub(/ -> .*$| link to .*$/, "", n)
          if (n == "paquet-reviseur/MANIFESTE.json") continue
          if (vu[n]++) { print "nom répété : " n; continue }
          if (type != "-") { print "membre d'"'"'un autre type (" type ") : " n; continue }
          if (!(n in taille)) { print "membre non déclaré : " n; continue }
          if (c[3] != taille[n]) print "taille " c[3] " au lieu de " taille[n] " : " n
        }
        for (d in taille) if (!(d in vu)) print "déclaré, non listé : " d
      }' "$AUX/$nom.tailles" < /dev/null | sort > "$AUX/$nom.liste-manifeste"
    liste "-- membres listés contre le manifeste (nom, type, taille)" "$AUX/$nom.liste-manifeste"
    ecarts=$((ecarts + $(grep -c '' "$AUX/$nom.liste-manifeste")))
  else
    echo "-- manifeste extrait : absent ou illisible"
    ecarts=$((ecarts + 1))
  fi

  # Résultat comparé à l'attendu de CT-8.
  if [ "$code" -eq 0 ]; then outil="accepte"; else outil="refuse"; fi
  if [ -s "$AUX/$nom.hors" ]; then
    verdict="DISCORDANCE (écriture hors de la destination)"
  elif [ "$sha_ok" -eq 0 ]; then
    verdict="DISCORDANCE (archive autre que celle de cas.json)"
  elif [ "$statut" = "intact" ]; then
    if [ "$outil" = "accepte" ] && [ "$ecarts" -eq 0 ]; then verdict="concorde"; else verdict="DISCORDANCE"; fi
  elif [ "$regle" = "PR-8" ]; then
    if [ "$ecarts" -gt 0 ] || [ "$outil" = "refuse" ]; then verdict="concorde"; else verdict="DISCORDANCE"; fi
  else
    if [ "$outil" = "refuse" ]; then verdict="concorde"; else verdict="limite_de_l_outil"; fi
  fi
  echo "-- résultat : tar $outil ; écarts au manifeste $ecarts ; verdict $verdict"
  case "$verdict" in
    concorde) concordes=$((concordes + 1)) ;;
    limite_de_l_outil) limites=$((limites + 1)) ;;
    *) discordances=$((discordances + 1)) ;;
  esac
done

echo
echo "== reconstruction de valide.tar par la recette d'EX-13.15"
dest="$TRAVAIL/extraits/valide/dest"
if [ -f "$dest/paquet-reviseur/MANIFESTE.json" ]; then
  secondes=$(date -u -d "$(jq -r '.created_at' "$dest/paquet-reviseur/MANIFESTE.json")" +%s)
  (cd "$dest" && find paquet-reviseur -type f | LC_ALL=C sort > "$AUX/liste-valide.txt" \
    && LC_ALL=C tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner \
      --mode=0644 --mtime=@"$secondes" -cf "$AUX/valide-gnu.tar" -T "$AUX/liste-valide.txt")
  reconstruit=$(sha256sum "$AUX/valide-gnu.tar" | cut -d' ' -f1)
  attendu_valide=$(jq -r '[.cases[] | select(.name == "valide")] | first | .archive_sha256 | ltrimstr("0x")' "$CAS")
  if cmp -s "$AUX/valide-gnu.tar" "$PAQUETS/valide.tar" && [ "$reconstruit" = "$attendu_valide" ]; then
    echo "cmp : identique octet pour octet ; mtime @$secondes ; sha256sum $reconstruit, égal à archive_sha256 du cas valide"
  else
    echo "cmp : DISCORDANCE, reconstruction différente de valide.tar ou de archive_sha256 du cas valide"
    discordances=$((discordances + 1))
  fi
else
  echo "valide.tar non extrait : DISCORDANCE"
  discordances=$((discordances + 1))
fi

echo
echo "# bilan : $archives archives ; concorde $concordes, limite_de_l_outil $limites, discordance $discordances"
[ "$discordances" -eq 0 ]
