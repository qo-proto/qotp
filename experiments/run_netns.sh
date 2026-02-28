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
  -h, --help      Print this help and exit
  --size MB       Data size in MB (default: 32)
  --rate RATE     Link rate, e.g. 1gbit, 100mbit (default: 1gbit)
  --out DIR       Output directory (default: experiments/results)
EOF
  exit
}

parse_params() {
  SIZE=32
  RATE="1gbit"
  OUT_DIR="$SCRIPT_DIR/results"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --size)
      SIZE="${2-}"
      shift
      ;;
    --rate)
      RATE="${2-}"
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

# Rate limit both directions
ip netns exec "$NS_SRV" tc qdisc add dev veth-srv root tbf rate "$RATE" burst 64kb latency 1ms
ip netns exec "$NS_CLI" tc qdisc add dev veth-cli root tbf rate "$RATE" burst 64kb latency 1ms

msg_info "Benchmark: ${SIZE} MB @ ${RATE}"
msg ""

# Start server in server namespace
ip netns exec "$NS_SRV" "$SCRIPT_DIR/server/server" -addr=10.0.0.1 >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

# Run client in client namespace
ip netns exec "$NS_CLI" "$SCRIPT_DIR/client/client" -addr=10.0.0.1 -size="$SIZE" -out="$OUT_DIR/combined.csv" 2>/tmp/qotp_debug.log
column -t -s, "$OUT_DIR/combined.csv"
msg ""
msg_ok "CSV written to $OUT_DIR/combined.csv"
