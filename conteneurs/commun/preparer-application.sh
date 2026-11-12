#!/bin/sh
# Préparation de l'arbre d'application d'une image noortrace/* Node.js, dans
# l'étape de construction (jamais dans l'image finale, qui n'a pas
# d'interpréteur de commandes).
#
#   preparer-application.sh <racine>
#
# <racine> contient package.json, package-lock.json, node_modules/ (écrit par
# `npm ci --omit=dev --workspace=…`) et paquets/. Le script :
#   1. garde sous paquets/ les seuls paquets que node_modules/@noortrace lie
#      (ceux que `npm ci` a installés) et supprime les autres ;
#   2. fixe les droits : répertoires 0755, fichiers 0644, programmes de bin/
#      0755, propriétaire 0:0 (les droits du dépôt ne dépendent plus du masque
#      de création de la machine qui construit) ;
#   3. remplace la ligne de lancement `#!/usr/bin/env node` des programmes de
#      bin/ par `#!/usr/local/bin/node` : l'image n'a ni /usr/bin/env ni
#      interpréteur, et le noyau exécute alors le programme directement (sonde
#      en forme CMD, CO-12) ; toute autre ligne de lancement arrête la
#      construction.
set -eu
racine="$1"
cd "$racine"
[ -d node_modules/@noortrace ] || { echo "preparer-application : node_modules/@noortrace absent" >&2; exit 1; }
gardes=""
for lien in node_modules/@noortrace/*; do
  cible="$(readlink "$lien")"
  case "$cible" in
    ../../paquets/*) ;;
    *) echo "preparer-application : lien inattendu $lien -> $cible" >&2; exit 1 ;;
  esac
  [ -d "$lien/" ] || { echo "preparer-application : lien cassé $lien" >&2; exit 1; }
  gardes="$gardes ${cible#../../paquets/}"
done
for rep in paquets/*; do
  nom="${rep#paquets/}"
  case " $gardes " in
    *" $nom "*) ;;
    *) rm -rf "$rep" ;;
  esac
done
chown -R 0:0 .
find . -type d -exec chmod 0755 {} +
find . -type f -exec chmod 0644 {} +
for prog in paquets/*/bin/*; do
  [ -f "$prog" ] || continue
  premiere="$(head -n 1 "$prog")"
  if [ "$premiere" != "#!/usr/bin/env node" ]; then
    echo "preparer-application : ligne de lancement inattendue dans $prog : $premiere" >&2
    exit 1
  fi
  sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' "$prog"
  chmod 0755 "$prog"
done
find . -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
echo "preparer-application : paquets gardés :$gardes"
