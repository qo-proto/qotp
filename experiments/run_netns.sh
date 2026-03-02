#!/usr/bin/env bash

set -Eeuo pipefail
trap 'cleanup $?' SIGINT SIGTERM ERR EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS_SRV="bench-srv"
NS_CLI="bench-cli"
SRV_PID=""

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
  if [[ -n "$SRV_PID" ]]; then
    kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  fi
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip netns del "$NS_CLI" 2>/dev/null || true
}

setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFMT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' BLUE='\033[0;34m'
  else
    NOFMT='' RED='' GREEN='' BLUE=''
  fi
}

msg() {
  echo >&2 -e "${1-}"
}

msg_ok() {
  msg "${GREEN}${1-}${NOFMT}"
}

msg_info() {
  msg "${BLUE}INFO: ${1-}${NOFMT}"
}

die() {
  msg "${RED}ERR: ${1-}${NOFMT}"
  exit "${2-1}"
}

usage() {
  cat <<EOF
Usage: sudo $(basename "${BASH_SOURCE[0]}") [OPTIONS]

Run benchmarks over a rate-limited veth pair using network namespaces.
Requires root.

OPTIONS:
  -h, --help          Print this help and exit
  --sizes LIST        Comma-separated data sizes in MB (default: 1,4,16,64)
  --rates LIST        Comma-separated link rates (default: 100mbit,500mbit,1gbit)
  --delays LIST       Comma-separated one-way delays (default: 0ms,20ms,50ms,100ms)
  --jitters LIST      Comma-separated jitter values (default: 0ms,5ms,10ms)
  --out DIR           Output directory (default: experiments/results)
EOF
  exit
}

parse_params() {
  SIZES="1,4,16,64"
  RATES="100mbit,500mbit,1gbit"
  DELAYS="0ms,20ms,50ms,100ms"
  JITTERS="0ms,5ms,10ms"
  OUT_DIR="$SCRIPT_DIR/results"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --sizes)
      SIZES="${2-}"
      shift
      ;;
    --rates)
      RATES="${2-}"
      shift
      ;;
    --delays)
      DELAYS="${2-}"
      shift
      ;;
    --jitters)
      JITTERS="${2-}"
      shift
      ;;
    --out)
      OUT_DIR="${2-}"
      shift
      ;;
    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done
}

setup_colors
parse_params "$@"

[[ $EUID -ne 0 ]] && die "This script must be run as root (sudo)."

mkdir -p "$OUT_DIR"

IFS=',' read -ra SIZE_ARR <<< "$SIZES"
IFS=',' read -ra RATE_ARR <<< "$RATES"
IFS=',' read -ra DELAY_ARR <<< "$DELAYS"
IFS=',' read -ra JITTER_ARR <<< "$JITTERS"

# Clean up stale namespaces from previous runs
ip netns del "$NS_SRV" 2>/dev/null || true
ip netns del "$NS_CLI" 2>/dev/null || true

# Create namespaces and veth pair
ip netns add "$NS_SRV"
ip netns add "$NS_CLI"
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns "$NS_SRV"
ip link set veth-cli netns "$NS_CLI"

# Assign addresses and bring up
ip netns exec "$NS_SRV" ip addr add 10.0.0.1/24 dev veth-srv
ip netns exec "$NS_SRV" ip link set veth-srv up
ip netns exec "$NS_SRV" ip link set lo up
ip netns exec "$NS_CLI" ip addr add 10.0.0.2/24 dev veth-cli
ip netns exec "$NS_CLI" ip link set veth-cli up
ip netns exec "$NS_CLI" ip link set lo up

# Start server in server namespace
ip netns exec "$NS_SRV" "$SCRIPT_DIR/server/server" -addr=10.0.0.1 >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

echo "protocol,size_mb,total_ms,scenario" > "$OUT_DIR/combined.csv"

for rate in "${RATE_ARR[@]}"; do
  for delay in "${DELAY_ARR[@]}"; do
    for jitter in "${JITTER_ARR[@]}"; do
      scenario="${rate}_${delay}_${jitter}"

      # netem for delay/jitter, then tbf for rate shaping
      for dev_ns in "$NS_SRV:veth-srv" "$NS_CLI:veth-cli"; do
        ns="${dev_ns%%:*}"
        dev="${dev_ns##*:}"
        ip netns exec "$ns" tc qdisc replace dev "$dev" root handle 1: netem delay "$delay" "$jitter"
        ip netns exec "$ns" tc qdisc replace dev "$dev" parent 1: handle 2: tbf rate "$rate" burst 64kb latency 1ms
      done

      for s in "${SIZE_ARR[@]}"; do
        msg_info "Benchmark: ${s} MB @ ${scenario}"
        ip netns exec "$NS_CLI" "$SCRIPT_DIR/client/client" \
          -addr=10.0.0.1 -size="$s" -scenario="$scenario" \
          >> "$OUT_DIR/combined.csv" 2>/tmp/qotp_debug.log
      done
    done
  done
done

msg ""
column -t -s, "$OUT_DIR/combined.csv"
msg ""
msg_ok "CSV written to $OUT_DIR/combined.csv"

if command -v gnuplot &>/dev/null; then
  gnuplot -e "csv='$OUT_DIR/combined.csv'; outdir='$OUT_DIR'" "$SCRIPT_DIR/plot.gp"
  msg_ok "Plots written to $OUT_DIR/"
else
  msg_info "Install gnuplot to generate charts automatically"
fi
