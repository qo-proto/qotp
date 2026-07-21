#!/usr/bin/env bash

set -Eeuo pipefail
trap 'cleanup $?' SIGINT SIGTERM ERR EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
  # Results must stay manageable by the invoking user, not root
  if [[ $EUID -eq 0 && -n "${SUDO_UID-}" && -d "${OUT_DIR-}" ]]; then
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT_DIR" 2>/dev/null || true
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
Usage: sudo $(basename "${BASH_SOURCE[0]}") [OPTIONS]

Run the full benchmark suite: solo baselines, lossy/RTT/reorder corners and
concurrent fairness across 10/50/100/500 mbit, then generate a summary
report (report.sh). Every measurement is repeated (default 3 runs) so
plots and report show mean and standard deviation. Requires root.
Takes ~45-60 minutes at 3 runs.

1gbit is deliberately excluded: three userspace stacks plus netem on one
machine measure the CPU, not the protocols. Watch the 500mbit rows for
early signs of CPU saturation instead.

OPTIONS:
  -h, --help    Print this help and exit
  --quick       Reduced matrix (100mbit only, single run) for iteration,
                ~4 minutes
  --runs N      Measurement repetitions per scenario (default: 3, quick: 1)
  --out DIR     Output directory; relative names are placed under
                experiments/results/ (default: results/suite)
EOF
  exit
}

parse_params() {
  QUICK=0
  RUNS=""
  OUT_DIR="suite"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --quick) QUICK=1 ;;
    --runs)
      RUNS="${2-}"
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

  # Explicit --runs wins; otherwise 3 for the full suite, 1 for --quick
  if [[ -z "$RUNS" ]]; then
    RUNS=$(( QUICK == 1 ? 1 : 3 ))
  fi
}

setup_colors
parse_params "$@"

[[ $EUID -ne 0 ]] && die "This script must be run as root (sudo)."
[[ -x "$SCRIPT_DIR/client/client" ]] || die "Build first: ./build.sh"

# All results live under experiments/results/: relative --out names are
# placed there, absolute paths are respected
[[ "$OUT_DIR" != /* ]] && OUT_DIR="$SCRIPT_DIR/results/$OUT_DIR"

# Ask once for the whole tree; scenario runs then clear their own subdirs
# via --yes without further prompting
if [[ -d "$OUT_DIR" && -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Previous suite results in $OUT_DIR — remove them first? [y/N] " ans
    [[ "$ans" =~ ^[Yy] ]] && rm -rf "${OUT_DIR:?}"/*
  fi
fi
mkdir -p "$OUT_DIR"

# size_for RATE_MBIT -> transfer size scaled so runs last ~5-20s per flow
size_for() {
  case "$1" in
  10) echo 8 ;;
  50) echo 32 ;;
  100) echo 64 ;;
  500) echo 128 ;;
  *) die "no size mapping for rate $1" ;;
  esac
}

# run NAME ARGS... -> one run_netns.sh invocation into its own subdir
run() {
  local name="$1"
  shift
  msg_info "=== scenario: $name"
  "$SCRIPT_DIR/run_netns.sh" --no-color --yes --runs "$RUNS" "$@" --out "$OUT_DIR/$name" \
    2>>"$OUT_DIR/suite.log" || die "scenario $name failed (see $OUT_DIR/suite.log)"
}

if [[ $QUICK -eq 1 ]]; then
  RATES=(100)
else
  RATES=(10 50 100 500)
fi

# Queues are specified as burst:latency, so the byte size of the queue
# (~rate x latency) scales with the link rate automatically:
#   40ms ~ 1x BDP at 40ms RTT (typical), 5ms ~ shallow corner
QUEUE_BDP="64kb:40ms"
QUEUE_SHALLOW="64kb:5ms"

# ── Solo baselines: each rate, clean link, BDP queue ─────────────────────────
for rate in "${RATES[@]}"; do
  run "solo_${rate}mbit" \
    --sizes "$(size_for "$rate")" --rates "${rate}mbit" \
    --delays 20ms --jitters 0ms --queues "$QUEUE_BDP"
done

# ── Solo corners (100mbit): loss, RTT extremes, jitter, reorder, queue ──────
run "solo_loss1" \
  --sizes 16 --rates 100mbit --delays 20ms --jitters 0ms \
  --losses 1% --queues "$QUEUE_BDP"
run "solo_loss3" \
  --sizes 16 --rates 100mbit --delays 20ms --jitters 0ms \
  --losses 3% --queues "$QUEUE_BDP"
run "solo_rtt_short" \
  --sizes 64 --rates 100mbit --delays 5ms --jitters 0ms --queues "$QUEUE_BDP"
run "solo_rtt_long" \
  --sizes 32 --rates 100mbit --delays 100ms --jitters 0ms --queues "$QUEUE_BDP"
run "solo_jitter" \
  --sizes 32 --rates 100mbit --delays 20ms --jitters 5ms --queues "$QUEUE_BDP"
run "solo_reorder2" \
  --sizes 16 --rates 100mbit --delays 20ms --jitters 0ms \
  --reorders 2% --queues "$QUEUE_BDP"
run "solo_shallow_queue" \
  --sizes 64 --rates 100mbit --delays 20ms --jitters 0ms \
  --queues "$QUEUE_SHALLOW"

# ── Fairness: 3-way concurrent at each rate, BDP queue ──────────────────────
for rate in "${RATES[@]}"; do
  run "fair3_${rate}mbit" \
    --sizes "$(size_for "$rate")" --rates "${rate}mbit" \
    --delays 20ms --jitters 0ms --queues "$QUEUE_BDP" \
    --proto tcp,qotp,quic
done

# ── Fairness corners (100mbit): shallow queue, lossy link, pairwise ─────────
run "fair3_shallow" \
  --sizes 64 --rates 100mbit --delays 20ms --jitters 0ms \
  --queues "$QUEUE_SHALLOW" --proto tcp,qotp,quic
run "fair3_loss1" \
  --sizes 64 --rates 100mbit --delays 20ms --jitters 0ms \
  --losses 1% --queues "$QUEUE_BDP" --proto tcp,qotp,quic
run "fair2_tcp_qotp" \
  --sizes 64 --rates 100mbit --delays 20ms --jitters 0ms \
  --queues "$QUEUE_BDP" --proto tcp,qotp
run "fair2_quic_qotp" \
  --sizes 64 --rates 100mbit --delays 20ms --jitters 0ms \
  --queues "$QUEUE_BDP" --proto quic,qotp

msg ""
msg_ok "All scenarios complete."
"$SCRIPT_DIR/report.sh" "$OUT_DIR"
