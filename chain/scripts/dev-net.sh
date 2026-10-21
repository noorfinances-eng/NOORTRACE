#!/usr/bin/env bash
# Lance, arrête et inspecte l'instance de développement DÉDIÉE de noorcore pour
# NOORTRACE : quatre validateurs BFT en boucle locale, sans émission ni jeton.
#
#   bash chain/scripts/dev-net.sh start    # démarre (idempotent, nœud par nœud)
#   bash chain/scripts/dev-net.sh stop     # arrête proprement les quatre nœuds
#   bash chain/scripts/dev-net.sh status   # état, hauteurs, ports (code 0 si les quatre sont debout)
#
# Pourquoi quatre validateurs et pas un : core/node/node.go refuse un jeu de
# validateurs de taille < 4 (« bft: validator set size < 4 not supported »).
# Quorum 2f+1 = 3, donc une faute tolérée.
#
# Matériel de validateur (clés secp256k1, validators.json) et données de chaîne
# vivent sous chain/runtime/ (gitignoré). Le matériel est généré UNE fois au
# premier start et réutilisé aux redémarrages : un jeu de clés neuf à chaque
# lancement ferait refuser la chaîne existante.
#
# Les nœuds sont détachés (setsid + nohup, entrée sur /dev/null, sortie dans les
# journaux) et survivent à la fin du terminal qui les a lancés.
#
# Variables d'environnement (facultatives) :
#   NOORTRACE_RUNTIME_DIR           répertoire d'exécution (défaut : chain/runtime)
#   NOORTRACE_BFT_RECOVERY_RESET=1  efface un marqueur de reprise BFT laissé par un
#                                   arrêt brutal (profil dev seulement, geste
#                                   explicite : ne jamais le poser par défaut)

set -euo pipefail

# --- identité de l'instance ---------------------------------------------------
# Identifiants à RÉSERVER pour NOORTRACE, distincts de 2121 (chaîne PoSS de
# NOORCHAIN), 2122 et 2123 (répétitions / pilote). 2124 = 0x84c.
CHAIN_ID="noortrace-2124-dev"
EVM_CHAIN_ID=2124
EVM_CHAIN_ID_HEX="0x84c"

# --- ports (boucle locale uniquement) ------------------------------------------
# Aucune collision avec les défauts de noorchain : RPC 8545, p2p 30303, santé
# 8080, ni avec la grappe de démo du hub (p2p 31301-31304, RPC 9546-9548).
NODES=(1 2 3 4)
RPC_PORTS=(8645 8646 8647 8648)
P2P_PORTS=(31400 31401 31402 31403)
HEALTH_PORTS=(8745 8746 8747 8748)
METRICS_PORTS=(9645 9646 9647 9648)

# --- chemins -------------------------------------------------------------------
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
chain_dir="$(cd -- "$script_dir/.." >/dev/null 2>&1 && pwd)"
RUNTIME_DIR="${NOORTRACE_RUNTIME_DIR:-$chain_dir/runtime}"
case "$RUNTIME_DIR" in /*) ;; *) RUNTIME_DIR="$PWD/$RUNTIME_DIR" ;; esac
BIN="$RUNTIME_DIR/bin/noorcore"
ALLOC_FILE="$chain_dir/config/alloc-dev.json"
KEYS_DIR="$RUNTIME_DIR/keys"
VALIDATORS_FILE="$RUNTIME_DIR/validators.json"
DATA_DIR="$RUNTIME_DIR/data"
LOG_DIR="$RUNTIME_DIR/logs"
PID_DIR="$RUNTIME_DIR/pids"

# --- pas d'émission, et que ce soit vrai quel que soit l'environnement ----------
# Le nœud lit ses règles d'émission dans NOOR_POSS_* (core/config/poss_emission_env.go)
# et les grave au premier boot. La section rules de alloc-dev.json déclare une
# chaîne SANS émission ; une variable qui traînerait dans l'environnement de
# l'opérateur ferait refuser le démarrage par le garde de genèse. On les efface
# donc ici, ainsi que la dérogation de fork, avant tout lancement.
unset NOOR_POSS_EMISSION_ENABLED NOOR_POSS_REWARDS_ADDRESS NOOR_POSS_EMISSION_CAP_WEI \
      NOOR_POSS_HALVING_PERIOD_SEC NOOR_POSS_GENESIS_UNIX NOOR_POSS_SUBPERIOD_SEC \
      NOOR_ACCEPT_NEW_EMISSION_PARAMS

# --- utilitaires --------------------------------------------------------------
rpc_brut() { # port méthode [params-json] -> corps de la réponse (vide si injoignable)
  curl -s -m 3 -X POST "http://127.0.0.1:$1" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" 2>/dev/null || true
}
rpc_resultat() { # port méthode [params-json] -> champ result (chaîne), vide sinon
  rpc_brut "$@" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'
}
port_ecoute() { # port -> 0 si quelqu'un écoute sur 127.0.0.1:port
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}
sante_http() { # port -> code HTTP de /healthz, ou « - »
  local code
  code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/healthz" 2>/dev/null || true)"
  [[ -n "$code" && "$code" != "000" ]] && echo "$code" || echo "-"
}
pid_de() { # i -> pid enregistré, ou échec
  local pf="$PID_DIR/node$1.pid"
  [[ -s "$pf" ]] && cat "$pf"
}
vivant() { [[ -n "${1:-}" ]] && kill -0 "$1" 2>/dev/null; }
notre_noeud() { # i -> 0 si le pid enregistré est un noorcore vivant lancé d'ici (même data-dir)
  local pid
  pid="$(pid_de "$1")" || return 1
  vivant "$pid" || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" | grep -qF -- "-data-dir $DATA_DIR/node$1 "
}
role_de() { [[ "$1" == "1" ]] && echo leader || echo follower; }

# --- matériel de validateur (une seule fois) ------------------------------------
generer_materiel() {
  command -v node >/dev/null 2>&1 || { echo "dev-net: node introuvable (nécessaire pour générer les clés secp256k1)" >&2; exit 1; }
  mkdir -p "$KEYS_DIR"
  chmod 700 "$KEYS_DIR"
  echo "dev-net: génération des quatre identités de validateur (secp256k1) sous $RUNTIME_DIR…"
  # Clés via le module crypto intégré à node (aucun paquet) : clé privée de 32
  # octets en hexadécimal, clé publique non compressée de 65 octets (préfixe
  # 04), le format que core/consensus/valset.go et signing.go attendent.
  # validators.json est écrit en DERNIER : sa présence atteste un matériel complet.
  KEYS_DIR="$KEYS_DIR" VALIDATORS_FILE="$VALIDATORS_FILE" node -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const validators = [];
    for (let i = 1; i <= 4; i++) {
      const ecdh = crypto.createECDH("secp256k1");
      ecdh.generateKeys();
      const priv = ecdh.getPrivateKey("hex").padStart(64, "0");
      const pub = ecdh.getPublicKey("hex");
      if (priv.length !== 64 || pub.length !== 130 || !pub.startsWith("04")) throw new Error("clé secp256k1 inattendue");
      fs.writeFileSync(`${process.env.KEYS_DIR}/node${i}.key`, priv + "\n", { mode: 0o600 });
      validators.push({ id: `v${i}`, pubKeyHex: "0x" + pub });
    }
    fs.writeFileSync(process.env.VALIDATORS_FILE, JSON.stringify({ validators }, null, 2) + "\n");
  '
  echo "dev-net: matériel écrit : $VALIDATORS_FILE, $KEYS_DIR/node{1..4}.key"
}
verifier_materiel() {
  local i
  for i in "${NODES[@]}"; do
    [[ -s "$KEYS_DIR/node$i.key" ]] || {
      echo "dev-net: $VALIDATORS_FILE existe mais $KEYS_DIR/node$i.key manque : matériel incohérent." >&2
      echo "  Pour repartir d'une chaîne neuve : stop, puis supprimer $KEYS_DIR, $VALIDATORS_FILE et $DATA_DIR." >&2
      exit 1
    }
  done
}

# --- lancement d'un nœud --------------------------------------------------------
lancer_noeud() {
  local i="$1" role peers="" j pf log
  role="$(role_de "$i")"
  for j in "${NODES[@]}"; do
    [[ "$j" == "$i" ]] && continue
    peers="${peers:+$peers,}127.0.0.1:${P2P_PORTS[$((j - 1))]}"
  done
  mkdir -p "$DATA_DIR/node$i"
  pf="$PID_DIR/node$i.pid"
  log="$LOG_DIR/node$i.log"
  rm -f "$pf"
  echo "=== dev-net: démarrage de node$i le $(date -Is) ===" >> "$log"
  # Le bash intermédiaire écrit SON pid puis fait exec du binaire : le pid
  # enregistré est donc bien celui de noorcore. setsid détache le nœud de la
  # session du terminal, nohup le rend sourd à SIGHUP.
  nohup setsid bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$pf" "$BIN" \
    -chain-id "$CHAIN_ID" \
    -evm-chain-id "$EVM_CHAIN_ID" \
    -data-dir "$DATA_DIR/node$i" \
    -p2p-addr "127.0.0.1:${P2P_PORTS[$((i - 1))]}" \
    -rpc-addr "127.0.0.1:${RPC_PORTS[$((i - 1))]}" \
    -health-addr "127.0.0.1:${HEALTH_PORTS[$((i - 1))]}" \
    -metrics-addr "127.0.0.1:${METRICS_PORTS[$((i - 1))]}" \
    -role "$role" \
    -consensus bft \
    -validator-id "v$i" \
    -validators-file "$VALIDATORS_FILE" \
    -validator-key-file "$KEYS_DIR/node$i.key" \
    -boot-peers "$peers" \
    -network-profile dev \
    "${RECOVERY_FLAG[@]}" \
    -alloc-file "$ALLOC_FILE" \
    >> "$log" 2>&1 < /dev/null &
  for _ in $(seq 1 50); do
    [[ -s "$pf" ]] && break
    sleep 0.1
  done
  [[ -s "$pf" ]] || { echo "dev-net: node$i : fichier pid non écrit, voir $log" >&2; exit 1; }
  echo "dev-net: node$i (v$i, $role) lancé — pid $(cat "$pf"), rpc ${RPC_PORTS[$((i - 1))]}, p2p ${P2P_PORTS[$((i - 1))]}, santé ${HEALTH_PORTS[$((i - 1))]}, métriques ${METRICS_PORTS[$((i - 1))]}, journal $log"
}

attendre_rpc() { # port délai_s -> 0 dès que eth_chainId répond
  local port="$1" n=$(( $2 * 2 ))
  for _ in $(seq 1 "$n"); do
    [[ -n "$(rpc_resultat "$port" eth_chainId)" ]] && return 0
    sleep 0.5
  done
  return 1
}
attendre_progression() { # port délai_s -> 0 dès que eth_blockNumber a strictement augmenté
  local port="$1" n=$(( $2 * 2 )) h0 h
  h0="$(rpc_resultat "$port" eth_blockNumber)"
  [[ -n "$h0" ]] || return 1
  for _ in $(seq 1 "$n"); do
    h="$(rpc_resultat "$port" eth_blockNumber)"
    if [[ -n "$h" ]] && (( h > h0 )); then
      echo "dev-net: la chaîne avance — hauteur $(( h0 )) -> $(( h ))"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# --- commandes ----------------------------------------------------------------
cmd_start() {
  command -v curl >/dev/null 2>&1 || { echo "dev-net: curl introuvable" >&2; exit 1; }
  [[ -f "$ALLOC_FILE" ]] || { echo "dev-net: genèse introuvable : $ALLOC_FILE" >&2; exit 1; }
  if [[ ! -x "$BIN" ]]; then
    echo "dev-net: binaire absent ($BIN), construction via build-noorcore.sh…"
    NOORTRACE_RUNTIME_DIR="$RUNTIME_DIR" bash "$script_dir/build-noorcore.sh"
  fi

  # Debout ? La question se pose PAR NŒUD : une grappe à moitié tombée est sous
  # son quorum et doit pouvoir être rattrapée. Un port qui répond pour une autre
  # chaîne, ou pour la nôtre mais depuis un processus qui n'est pas le nôtre,
  # est un blocage, jamais pris pour notre nœud.
  local i port trouve manquants=()
  for i in "${NODES[@]}"; do
    port="${RPC_PORTS[$((i - 1))]}"
    trouve="$(rpc_resultat "$port" eth_chainId)"
    if [[ -z "$trouve" ]]; then
      if notre_noeud "$i"; then
        echo "dev-net: node$i est en cours de démarrage (pid $(pid_de "$i")), RPC pas encore prêt"
      elif port_ecoute "$port"; then
        echo "dev-net: le port $port est tenu par un processus qui ne répond pas en JSON-RPC : à libérer d'abord" >&2
        exit 1
      else
        manquants+=("$i")
      fi
    elif [[ "$trouve" != "$EVM_CHAIN_ID_HEX" ]]; then
      echo "dev-net: le port $port répond pour la chaîne $trouve, pas $EVM_CHAIN_ID_HEX ($EVM_CHAIN_ID) : un autre réseau tient ce port, à arrêter d'abord" >&2
      exit 1
    elif ! notre_noeud "$i"; then
      echo "dev-net: le port $port répond pour la chaîne $EVM_CHAIN_ID, mais pas depuis un nœud lancé d'ici ($DATA_DIR/node$i) : une autre grappe de même numéro tient ce port, à arrêter d'abord" >&2
      exit 1
    fi
  done
  if [[ ${#manquants[@]} -eq 0 ]]; then
    echo "dev-net: les quatre validateurs sont déjà debout (chaîne $CHAIN_ID, evm $EVM_CHAIN_ID)"
    cmd_status
    return
  fi
  for i in "${manquants[@]}"; do
    for port in "${P2P_PORTS[$((i - 1))]}" "${HEALTH_PORTS[$((i - 1))]}" "${METRICS_PORTS[$((i - 1))]}"; do
      if port_ecoute "$port"; then
        echo "dev-net: le port $port (node$i) est déjà pris par un autre processus : à libérer d'abord" >&2
        exit 1
      fi
    done
    rm -f "$PID_DIR/node$i.pid"
  done
  echo "dev-net: à démarrer — node${manquants[*]} ; chaîne $CHAIN_ID (evm $EVM_CHAIN_ID), genèse $ALLOC_FILE, exécution $RUNTIME_DIR"

  mkdir -p "$DATA_DIR" "$LOG_DIR" "$PID_DIR"
  if [[ ! -s "$VALIDATORS_FILE" ]]; then
    generer_materiel
  else
    verifier_materiel
  fi

  # Reprise après un arrêt brutal : un nœud BFT tué en plein round laisse un
  # marqueur et REFUSE de redémarrer (« stale BFT recovery marker »). C'est
  # voulu : il ne reprend pas en silence depuis un état de consensus incertain.
  # Le geste est opt-in et dev seulement.
  RECOVERY_FLAG=()
  if [[ "${NOORTRACE_BFT_RECOVERY_RESET:-0}" == "1" ]]; then
    echo "dev-net: marqueur de reprise BFT effacé sur demande explicite (profil dev)"
    RECOVERY_FLAG=(-bft-recovery-reset)
  fi

  for i in "${manquants[@]}"; do
    lancer_noeud "$i"
  done

  for i in "${manquants[@]}"; do
    port="${RPC_PORTS[$((i - 1))]}"
    if ! attendre_rpc "$port" 60; then
      echo "dev-net: le RPC de node$i (127.0.0.1:$port) ne répond pas après 60 s — voir $LOG_DIR/node$i.log" >&2
      exit 1
    fi
  done
  echo "dev-net: les quatre validateurs sont debout, quorum 3 — RPC principal sur 127.0.0.1:${RPC_PORTS[0]}"
  if ! attendre_progression "${RPC_PORTS[0]}" 120; then
    echo "dev-net: la hauteur n'a pas progressé en 120 s — voir $LOG_DIR/node1.log" >&2
    exit 1
  fi
  cmd_status
}

cmd_stop() {
  local i pid restants=()
  for i in "${NODES[@]}"; do
    if notre_noeud "$i"; then
      pid="$(pid_de "$i")"
      kill -TERM "$pid" 2>/dev/null && echo "dev-net: node$i : arrêt demandé (pid $pid)"
      restants+=("$i")
    elif [[ -f "$PID_DIR/node$i.pid" ]]; then
      echo "dev-net: node$i : pas en marche (fichier pid périmé, retiré)"
      rm -f "$PID_DIR/node$i.pid"
    else
      echo "dev-net: node$i : pas en marche"
    fi
  done
  # Arrêt propre d'abord (SIGTERM : le nœud ferme son état de consensus), un
  # KILL seulement en dernier recours, car il peut laisser un marqueur de reprise.
  local encore
  for _ in $(seq 1 60); do
    encore=0
    for i in "${restants[@]}"; do vivant "$(pid_de "$i" || true)" && encore=1; done
    [[ "$encore" -eq 0 ]] && break
    sleep 0.5
  done
  for i in "${restants[@]}"; do
    pid="$(pid_de "$i" || true)"
    if vivant "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
      echo "dev-net: node$i : arrêt forcé après 30 s (un marqueur de reprise BFT peut rester : relancer avec NOORTRACE_BFT_RECOVERY_RESET=1)" >&2
    else
      echo "dev-net: node$i : arrêté"
    fi
    rm -f "$PID_DIR/node$i.pid"
  done
}

cmd_status() {
  local i pid etat trouve hauteur sante debout=0 rpc
  echo "dev-net: chaîne $CHAIN_ID (evm $EVM_CHAIN_ID = $EVM_CHAIN_ID_HEX) — exécution : $RUNTIME_DIR"
  [[ -x "$BIN" ]] && echo "dev-net: binaire : $BIN" || echo "dev-net: binaire ABSENT ($BIN) — lancer build-noorcore.sh"
  [[ -s "$VALIDATORS_FILE" ]] && echo "dev-net: matériel : $VALIDATORS_FILE (+ clés sous $KEYS_DIR)" || echo "dev-net: matériel : pas encore généré (au premier start)"
  for i in "${NODES[@]}"; do
    rpc="${RPC_PORTS[$((i - 1))]}"
    if notre_noeud "$i"; then
      pid="$(pid_de "$i")"; etat="en marche (pid $pid)"
    elif [[ -f "$PID_DIR/node$i.pid" ]]; then
      etat="ARRÊTÉ (fichier pid périmé)"
    else
      etat="arrêté"
    fi
    trouve="$(rpc_resultat "$rpc" eth_chainId)"
    hauteur="$(rpc_resultat "$rpc" eth_blockNumber)"
    sante="$(sante_http "${HEALTH_PORTS[$((i - 1))]}")"
    if [[ "$trouve" == "$EVM_CHAIN_ID_HEX" ]] && notre_noeud "$i"; then debout=$((debout + 1)); fi
    printf 'node%d (v%d, %-8s) : %-24s | rpc 127.0.0.1:%d chainId %-6s | hauteur %-8s | santé %s\n' \
      "$i" "$i" "$(role_de "$i")" "$etat" "$rpc" "${trouve:--}" "${hauteur:+$(( hauteur )) ($hauteur)}" "$sante"
  done
  echo "dev-net: $debout/4 validateurs debout (quorum 3 requis) ; journaux sous $LOG_DIR"
  [[ "$debout" -eq 4 ]]
}

usage() {
  sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  -h|--help|help|"") usage; [[ "${1:-}" == "" ]] && exit 2 || exit 0 ;;
  *) echo "dev-net: commande inconnue : $1 (attendu : start | stop | status)" >&2; exit 2 ;;
esac
