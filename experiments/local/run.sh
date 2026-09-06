#!/usr/bin/env bash

set -Eeuo pipefail
trap 'cleanup $?' SIGINT SIGTERM ERR EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRV_PID=""

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
  if [[ -n "$SRV_PID" ]]; then
    kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  fi
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
Usage: $(basename "${BASH_SOURCE[0]}") [OPTIONS]

Run QOTP/TCP/QUIC head-to-head on THIS machine, both directions, solo
and in parallel. For two real machines see ../remote/run.sh.

Without --netns everything shares the loopback interface, which has no
bottleneck: solo throughput is meaningful, fairness is not. Use --netns
(needs root) for a real rate-limited link.

OPTIONS:
  -h, --help        Print this help and exit
  --netns           Run over a rate-limited veth pair between two network
                    namespaces (requires root)
  --rate RATE       Bottleneck rate for --netns (default: 100mbit)
  --delay DELAY     One-way delay for --netns (default: 10ms)
  --queue N         Bottleneck queue in packets for --netns. Default is one
                    bandwidth-delay product, computed from --rate/--delay.
                    netem's own default (1000) is several BDP of drop-tail
                    buffer, which bufferbloats the link and makes the
                    fairness numbers swing wildly between runs.
  --jitter J        Delay variation for --netns (e.g. 5ms; default: none)
  --loss PCT        Random loss for --netns (e.g. 1%; default: none)
  --reorder PCT     Packet reordering for --netns (needs --delay > 0)
  --aqm NAME        Bottleneck queue management: none (tail-drop, the
                    default) or fq_codel (per-flow fairness enforced by the
                    queue rather than by the protocols)
  --duration D      Measure for D per transfer instead of a fixed size.
                    Preferred for fairness: every flow is then measured over
                    the same steady-state window.
  --size MB         MB per protocol per direction (default: 32)
  --port N          Base port; qotp=N, tcp=N+1, quic=N+2 (default: 9000).
                    Change this if something already listens on those.
  --runs N          Repeat N times and report median [min-max] (default: 3).
                    One run of a fairness measurement is noise.
  --out DIR         Output directory; relative names are placed under
                    experiments/results/ (default: results/manual)
EOF
  exit
}

parse_params() {
  OUT_DIR="manual"
  NETNS=0
  RATE="100mbit"
  DELAY="10ms"
  QUEUE=""
  JITTER=""
  LOSS=""
  REORDER=""
  AQM="none"
  DURATION=""
  SIZE="32"
  RUNS="3"
  PORT="9000"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --netns) NETNS=1 ;;
    --rate) RATE="${2-}"; shift ;;
    --delay) DELAY="${2-}"; shift ;;
    --queue) QUEUE="${2-}"; shift ;;
    --jitter) JITTER="${2-}"; shift ;;
    --loss) LOSS="${2-}"; shift ;;
    --reorder) REORDER="${2-}"; shift ;;
    --aqm) AQM="${2-}"; shift ;;
    --duration) DURATION="${2-}"; shift ;;
    --size) SIZE="${2-}"; shift ;;
    --port) PORT="${2-}"; shift ;;
    --runs) RUNS="${2-}"; shift ;;
    --out) OUT_DIR="${2-}"; shift ;;
    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done
}

# bdp_packets RATE DELAY -> one bandwidth-delay product, in full-size packets.
# Sizing the bottleneck queue to ~1 BDP is what makes fairness reproducible;
# a deep drop-tail queue lets a loss-based flow fill it and starve the rest,
# and which flow wins then depends on startup order.
bdp_packets() {
  local rate="$1" delay="$2" bits ms
  case "$rate" in
    *gbit) bits=$(( ${rate%gbit} * 1000000000 )) ;;
    *mbit) bits=$(( ${rate%mbit} * 1000000 )) ;;
    *kbit) bits=$(( ${rate%kbit} * 1000 )) ;;
    *) bits="$rate" ;;
  esac
  ms="${delay%ms}"
  echo $(( bits / 8 * 2 * ms / 1000 / 1452 + 1 ))
}

setup_colors
parse_params "$@"

# All results live under experiments/results/: relative --out names are
# placed there, absolute paths are respected
[[ "$OUT_DIR" != /* ]] && OUT_DIR="$ROOT_DIR/results/$OUT_DIR"
mkdir -p "$OUT_DIR"

CLI_ARGS=(-size "$SIZE" -runs "$RUNS" -port "$PORT" -json "$OUT_DIR/result.json")
[[ -n "$DURATION" ]] && CLI_ARGS+=(-duration "$DURATION")

if [[ "$NETNS" -eq 0 ]]; then
  msg_info "Loopback (no bottleneck): solo numbers are real, fairness is not."
  "$ROOT_DIR/qotp-bench" -listen -addr 127.0.0.1 -port "$PORT" > "$OUT_DIR/server.log" 2>&1 &
  SRV_PID=$!
  trap 'kill $SRV_PID 2>/dev/null || true' EXIT
  sleep 1
  grep -q READY "$OUT_DIR/server.log" || die "server failed to start: $(cat "$OUT_DIR/server.log")"
  "$ROOT_DIR/qotp-bench" -addr 127.0.0.1 "${CLI_ARGS[@]}" | tee "$OUT_DIR/report.txt"
else
  [[ "$(id -u)" -eq 0 ]] || die "--netns requires root"
  [[ -z "$QUEUE" ]] && QUEUE="$(bdp_packets "$RATE" "$DELAY")"
  msg_info "netns link: $RATE, $DELAY each way, queue ${QUEUE} pkts (~1 BDP)"

  cleanup_ns() {
    ip netns del qotp-srv 2>/dev/null || true
    ip netns del qotp-cli 2>/dev/null || true
  }
  trap cleanup_ns EXIT
  cleanup_ns

  ip netns add qotp-srv
  ip netns add qotp-cli
  ip link add vsrv type veth peer name vcli
  ip link set vsrv netns qotp-srv
  ip link set vcli netns qotp-cli
  ip netns exec qotp-srv ip addr add 10.9.0.1/24 dev vsrv
  ip netns exec qotp-cli ip addr add 10.9.0.2/24 dev vcli
  ip netns exec qotp-srv ip link set vsrv up
  ip netns exec qotp-cli ip link set vcli up
  ip netns exec qotp-srv ip link set lo up
  ip netns exec qotp-cli ip link set lo up
  # netem argument order matters: delay and its jitter must stay adjacent,
  # and reorder is only meaningful once there is a delay to reorder within.
  NETEM=(rate "$RATE" delay "$DELAY")
  [[ -n "$JITTER" ]] && NETEM+=("$JITTER")
  [[ -n "$LOSS" ]] && NETEM+=(loss "$LOSS")
  [[ -n "$REORDER" ]] && NETEM+=(reorder "$REORDER" 50%)
  NETEM+=(limit "$QUEUE")

  # Shape both directions: the bottleneck must be symmetric or the reverse
  # path silently becomes the limit.
  for ns_dev in "qotp-srv vsrv" "qotp-cli vcli"; do
    set -- $ns_dev
    if [[ "$AQM" == "fq_codel" ]]; then
      ip netns exec "$1" tc qdisc add dev "$2" root handle 1: netem "${NETEM[@]}"
      ip netns exec "$1" tc qdisc add dev "$2" parent 1: handle 10: fq_codel
    else
      ip netns exec "$1" tc qdisc add dev "$2" root netem "${NETEM[@]}"
    fi
  done
  msg_info "netem: ${NETEM[*]}, aqm=$AQM"

  ip netns exec qotp-srv "$ROOT_DIR/qotp-bench" -listen -addr 10.9.0.1 -port "$PORT" \
    > "$OUT_DIR/server.log" 2>&1 &
  sleep 1
  grep -q READY "$OUT_DIR/server.log" || die "server failed to start: $(cat "$OUT_DIR/server.log")"
  ip netns exec qotp-cli "$ROOT_DIR/qotp-bench" -addr 10.9.0.1 "${CLI_ARGS[@]}" \
    | tee "$OUT_DIR/report.txt"
fi

msg ""
msg_ok "Report written to $OUT_DIR/report.txt"
