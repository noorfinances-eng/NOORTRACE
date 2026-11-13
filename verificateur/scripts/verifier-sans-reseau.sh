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
  # Artefact de strace à la sortie du processus. Quand un fil s'arrête à
  # l'entrée d'un appel système et que le processus se termine (exit_group)
  # avant que strace ait lu cet arrêt, PTRACE_GET_SYSCALL_INFO (ou
  # PTRACE_GETREGS) rend ESRCH : strace ne connaît pas le numéro de l'appel et
  # écrit son nom « ??? » quel que soit le filtre (src/syscall.c,
  # syscall_entering_decode et get_scno, strace 6.8 et 6.19). Le noyau
  # n'exécute pas un appel dont l'arrêt d'entrée se termine par une mort
  # (syscall_trace_enter rend -1 quand un signal fatal est en attente). La
  # ligne est ensuite fermée de l'une de quatre façons, et de nulle autre :
  #   PID ???( <detached ...>        le fil disparaît (droptcb) ;
  #   PID ???( <unfinished ...>      la ligne d'un autre fil commence (printleader) ;
  #   PID ???()   = ?                arrêt PTRACE_EVENT_EXIT du fil, quand son
  #                                  arrêt « ??? » était son premier appel
  #                                  observé (print_event_exit) ;
  #   PID <... ??? resumed>)   = ?   le même, après la ligne d'un autre fil.
  # Toute autre ligne, dont tout appel nommé de la classe %network, est un
  # appel réseau. Une exécution dont la trace ne contient que des artefacts
  # est relancée, au plus cinq fois, et le cas n'est réussi que sur une trace
  # vide (EX-14.5 : trace.txt vide exigé).
  artefact='^[0-9]+ +(\?\?\?\( <(detached|unfinished) \.\.\.>|(\?\?\?\(|<\.\.\. \?\?\? resumed>)\) += \?)$'
  # classer <trace> : 0 trace vide, 1 artefacts seulement, 2 au moins un appel.
  classer() {
    [ -s "$1" ] || return 0
    if grep -qvE "$artefact" "$1"; then return 2; fi
    return 1
  }

  # Témoin : un programme qui appelle socket(AF_INET, SOCK_STREAM, 0) doit
  # être relevé et refusé par la même analyse, sur le strace de la machine.
  mkdir "$tmp/temoin"
  printf '%s\n' 'package main' '' 'import "syscall"' '' 'func main() {' \
    '	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)' \
    '	if err == nil {' '		syscall.Close(fd)' '	}' '}' >"$tmp/temoin/main.go"
  (cd "$tmp/temoin" && GOTOOLCHAIN=local GOENV=off GOFLAGS= GOPROXY=off CGO_ENABLED=0 go build -o "$tmp/temoin/socket" main.go)
  set +e; strace -f -qq -e trace=%network -e signal=none -o "$tmp/temoin.txt" "$tmp/temoin/socket" >/dev/null 2>&1; set -e
  r=0; classer "$tmp/temoin.txt" || r=$?
  if [ "$r" -eq 2 ] && grep -qE '^[0-9]+ +socket\(AF_INET, SOCK_STREAM' "$tmp/temoin.txt"; then
    echo "   témoin socket() : appel relevé et refusé par l'analyse"
  else
    echo "   ÉCHEC : le témoin socket() n'est pas refusé par l'analyse (classe $r)"; cat "$tmp/temoin.txt"
    echecs=$((echecs + 1))
  fi

  lignes=0
  relances=0
  for c in "${cas[@]}"; do
    essai=0
    while :; do
      essai=$((essai + 1))
      # shellcheck disable=SC2086
      set +e; strace -f -qq -e trace=%network -e signal=none -o "$tmp/trace.txt" "$binaire" $c >/dev/null 2>&1; set -e
      r=0; classer "$tmp/trace.txt" || r=$?
      [ "$r" -eq 0 ] && break
      if [ "$r" -eq 2 ] || [ "$essai" -ge 5 ]; then
        echo "   ÉCHEC : $c"
        if [ "$r" -eq 2 ]; then
          grep -vE "$artefact" "$tmp/trace.txt" | head -3 || true
        else
          echo "   artefacts seulement, cinq fois de suite :"; head -3 "$tmp/trace.txt"
        fi
        lignes=$((lignes + $(wc -l <"$tmp/trace.txt"))); break
      fi
      relances=$((relances + 1))
    done
  done
  if [ "$relances" -ne 0 ]; then
    echo "   $relances exécution(s) relancée(s) après un artefact « ??? » de strace à la sortie du processus"
  fi
  if [ "$lignes" -eq 0 ]; then echo "   trace vide pour chaque exécution : réussi"; else echecs=$((echecs + 1)); fi
fi

if [ "$echecs" -ne 0 ]; then echo "preuves d'absence de réseau : $echecs en échec"; exit 1; fi
if [ "$impossible" -ne 0 ]; then echo "preuves d'absence de réseau : incomplètes (voir ci-dessus)"; exit 3; fi
echo "preuves d'absence de réseau : les quatre réussies"
