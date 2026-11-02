#!/usr/bin/env bash
# Preuves d'absence de réseau du binaire noortrace-verifier (CT-6 EX-14.5).
#
# Usage : scripts/verifier-sans-reseau.sh [<binaire>]
#
# Sans argument, le binaire est construit par scripts/construire.sh dans un
# répertoire temporaire. Les quatre preuves d'EX-14.5 :
#   1. go list -deps ./... ne contient ni net/http, ni crypto/tls, ni os/exec ;
#   2. go tool nm <binaire> ne contient aucun symbole net.(*Resolver) ni
#      net.(*Dialer) ;
#   3. unshare -n <binaire> <vecteurs> rend le même code de retour et le même
#      rapport JSON qu'hors isolement (V-8) ;
#   4. strace -f -e trace=%network <binaire> <vecteurs> n'écrit aucune ligne.
#
# Une preuve que la machine ne permet pas (unshare ou strace absents ou
# refusés) n'est pas simulée : le script le dit et rend le code 3.
set -euo pipefail

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
depot="$(cd "$ici/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

binaire="${1:-}"
if [ -z "$binaire" ]; then
  "$ici/scripts/construire.sh" -o "$tmp/noortrace-verifier" >/dev/null
  binaire="$tmp/noortrace-verifier"
fi

echecs=0
impossible=0

echo "1. go list -deps : net/http, crypto/tls, os/exec"
interdits="$(cd "$ici" && GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 go list -deps ./... | grep -E '^(net/http|crypto/tls|os/exec)$' || true)"
if [ -n "$interdits" ]; then
  echo "   ÉCHEC : $interdits"; echecs=$((echecs + 1))
else
  echo "   sortie vide : réussi"
fi

echo "2. go tool nm : net.(*Resolver), net.(*Dialer)"
symboles="$(go tool nm "$binaire" | grep -E ' net\.\(\*(Resolver|Dialer)\)' || true)"
if [ -n "$symboles" ]; then
  echo "   ÉCHEC :"; echo "$symboles" | head -5; echecs=$((echecs + 1))
else
  echo "   sortie vide : réussi"
fi

# Vecteurs rejoués : les dossiers de CT-1 (sans ancres, puis avec le fichier
# d'ancres de test) et un dossier de CT-6.
ancres="$depot/spec/vecteurs/ct-6/ancres/ancres-test.json"
entetes="$depot/spec/vecteurs/ct-6/ots/entetes/chaine.json"
cas=()
for d in "$depot"/spec/vecteurs/ct-1/dossiers/*/; do
  cas+=("$d --json")
  cas+=("$d --json --ancres $ancres")
done
cas+=("$depot/spec/vecteurs/ct-6/dossiers/valide-seq-7-complet --json --ancres $ancres --entetes-bitcoin $entetes")
cas+=("$depot/spec/vecteurs/ct-6/dossiers/valide-decision-refusee --json")

echo "3. unshare -n : même code de retour et même rapport qu'hors isolement (${#cas[@]} exécutions)"
if ! command -v unshare >/dev/null || ! unshare -n true 2>/dev/null; then
  echo "   NON UTILISABLE sur cette machine (unshare absent ou refusé) : preuve non faite"; impossible=1
else
  ecarts=0
  for c in "${cas[@]}"; do
    # shellcheck disable=SC2086
    set +e; "$binaire" $c >"$tmp/a.json" 2>/dev/null; ca=$?
    unshare -n "$binaire" $c >"$tmp/b.json" 2>/dev/null; cb=$?; set -e
    if [ "$ca" != "$cb" ] || ! cmp -s "$tmp/a.json" "$tmp/b.json"; then
      echo "   ÉCART : $c (codes $ca et $cb)"; ecarts=$((ecarts + 1))
    fi
  done
  if [ "$ecarts" -eq 0 ]; then echo "   aucun écart : réussi"; else echecs=$((echecs + 1)); fi
fi

echo "4. strace -f -e trace=%network : aucun appel réseau (${#cas[@]} exécutions)"
if ! command -v strace >/dev/null || ! strace -f -qq -e trace=%network -e signal=none -o "$tmp/essai.txt" true 2>/dev/null; then
  echo "   NON UTILISABLE sur cette machine (strace absent ou refusé) : preuve non faite"; impossible=1
else
  # Chaque exécution doit laisser une trace vide. Une seule exception est
  # reconnue, et elle n'est pas comptée comme réussie : la ligne
  # « ??? ( <detached ...> » (ou « <unfinished ...> ») qu'écrit strace quand
  # le processus se termine (exit_group) pendant qu'un fil de l'exécutif Go
  # entre dans un appel système que strace ne peut plus décoder. L'exécution
  # est alors relancée, jusqu'à cinq fois, et le cas n'est réussi que sur une
  # trace vide.
  lignes=0
  relances=0
  for c in "${cas[@]}"; do
    essai=0
    while :; do
      essai=$((essai + 1))
      # shellcheck disable=SC2086
      set +e; strace -f -qq -e trace=%network -e signal=none -o "$tmp/trace.txt" "$binaire" $c >/dev/null 2>&1; set -e
      n="$(wc -l <"$tmp/trace.txt")"
      [ "$n" -eq 0 ] && break
      autres="$(grep -vE '^[0-9]+ +(\?\?\?\( <(detached|unfinished) \.\.\.>|<\.\.\. \?\?\? resumed>\) += \?)$' "$tmp/trace.txt" || true)"
      if [ -n "$autres" ] || [ "$essai" -ge 5 ]; then
        echo "   ÉCHEC : $c"; head -3 "$tmp/trace.txt"; lignes=$((lignes + n)); break
      fi
      relances=$((relances + 1))
    done
  done
  if [ "$relances" -ne 0 ]; then
    echo "   $relances exécution(s) relancée(s) après l'artefact « ??? <detached ...> » de strace à la sortie du processus"
  fi
  if [ "$lignes" -eq 0 ]; then echo "   trace vide pour chaque exécution : réussi"; else echecs=$((echecs + 1)); fi
fi

if [ "$echecs" -ne 0 ]; then echo "preuves d'absence de réseau : $echecs en échec"; exit 1; fi
if [ "$impossible" -ne 0 ]; then echo "preuves d'absence de réseau : incomplètes (voir ci-dessus)"; exit 3; fi
echo "preuves d'absence de réseau : les quatre réussies"
