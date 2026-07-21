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
  # Restore the global socket buffer caps we raised
  if [[ -n "${OLD_RMEM_MAX-}" ]]; then
    sysctl -qw net.core.rmem_max="$OLD_RMEM_MAX" net.core.wmem_max="$OLD_WMEM_MAX" 2>/dev/null || true
  fi
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

Run benchmarks over a rate-limited veth pair using network namespaces.
Requires root.

OPTIONS:
  -h, --help          Print this help and exit
  --sizes LIST        Comma-separated data sizes in MB (default: 1,4,16,64)
  --rates LIST        Comma-separated link rates (default: 100mbit,500mbit,1gbit)
  --delays LIST       Comma-separated one-way delays (default: 0ms,20ms,50ms,100ms)
  --jitters LIST      Comma-separated jitter values (default: 0ms,5ms,10ms)
  --losses LIST       Comma-separated random loss rates (default: 0%)
  --reorders LIST     Comma-separated reorder rates (default: 0%; needs delay > 0)
  --queues LIST       Comma-separated bottleneck queues as burst:latency
                      (default: 64kb:1ms; e.g. 64kb:1ms,256kb:50ms)
  --proto LIST        Protocols to run CONCURRENTLY through the same
                      bottleneck (tcp,qotp,quic), with per-protocol rate
                      timelines written to rates_*.csv. A single value runs
                      that protocol standalone. Default: unset — all three
                      run sequentially (isolated measurement).
  --out DIR           Output directory; relative names are placed under
                      experiments/results/ (default: results/manual)
  --runs N            Repeat each measurement N times (default: 1); plots
                      and reports then show mean and standard deviation
  --yes               Remove previous results in the output directory
                      without asking (used by suite.sh)

The scenario is the cross product of all lists — vary one dimension at a
time to keep run counts manageable.
EOF
  exit
}

parse_params() {
  SIZES="1,4,16,64"
  RATES="100mbit,500mbit,1gbit"
  DELAYS="0ms,20ms,50ms,100ms"
  JITTERS="0ms,5ms,10ms"
  LOSSES="0%"
  REORDERS="0%"
  QUEUES="64kb:1ms"
  PROTO=""
  OUT_DIR="manual"
  ASSUME_YES=0
  RUNS=1

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
    --losses)
      LOSSES="${2-}"
      shift
      ;;
    --reorders)
      REORDERS="${2-}"
      shift
      ;;
    --queues)
      QUEUES="${2-}"
      shift
      ;;
    --proto)
      PROTO="${2-}"
      shift
      ;;
    --out)
      OUT_DIR="${2-}"
      shift
      ;;
    --runs)
      RUNS="${2-}"
      shift
      ;;
    --yes) ASSUME_YES=1 ;;
    -?*) die "Unknown option: $1" ;;
    *) break
    esac
    shift
  done
}

setup_colors
parse_params "$@"

[[ $EUID -ne 0 ]] && die "This script must be run as root (sudo)."

# All results live under experiments/results/: relative --out names are
# placed there, absolute paths are respected
[[ "$OUT_DIR" != /* ]] && OUT_DIR="$SCRIPT_DIR/results/$OUT_DIR"

# Stale artifacts (old rates_*.csv, plots) in a reused output directory mix
# into reports — offer to clear them first
if [[ -d "$OUT_DIR" && -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then
    rm -rf "${OUT_DIR:?}"/*
  elif [[ -t 0 ]]; then
    read -r -p "Previous results in $OUT_DIR — remove them first? [y/N] " ans
    [[ "$ans" =~ ^[Yy] ]] && rm -rf "${OUT_DIR:?}"/*
  fi
fi
mkdir -p "$OUT_DIR"

IFS=',' read -ra SIZE_ARR <<< "$SIZES"
IFS=',' read -ra RATE_ARR <<< "$RATES"
IFS=',' read -ra DELAY_ARR <<< "$DELAYS"
IFS=',' read -ra JITTER_ARR <<< "$JITTERS"
IFS=',' read -ra LOSS_ARR <<< "$LOSSES"
IFS=',' read -ra REORDER_ARR <<< "$REORDERS"
IFS=',' read -ra QUEUE_ARR <<< "$QUEUES"

# Raise the global UDP socket buffer caps so the stacks' 7MB requests are
# honored (net.core.* is global, not per-namespace); restored in cleanup.
# Default rmem_max (~200KB) is only ~3ms of headroom at 500mbit — process
# scheduling pauses then overflow the socket, which looks like path loss.
OLD_RMEM_MAX=$(sysctl -n net.core.rmem_max)
OLD_WMEM_MAX=$(sysctl -n net.core.wmem_max)
sysctl -qw net.core.rmem_max=8388608 net.core.wmem_max=8388608

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
      for loss in "${LOSS_ARR[@]}"; do
        for reorder in "${REORDER_ARR[@]}"; do
          for queue in "${QUEUE_ARR[@]}"; do
            burst="${queue%%:*}"
            qlat="${queue##*:}"

            # Scenario label: base dims always, extra dims only when
            # non-default — keeps labels comparable with older CSVs
            scenario="${rate}_${delay}_${jitter}"
            [[ "$loss" != "0%" ]] && scenario+="_l${loss%\%}"
            [[ "$reorder" != "0%" ]] && scenario+="_r${reorder%\%}"
            [[ "$queue" != "64kb:1ms" ]] && scenario+="_q${burst}-${qlat}"

            # netem for delay/jitter/loss/reorder, then tbf for rate
            # shaping. reorder only takes effect with delay > 0: reordered
            # packets jump the delay queue.
            netem_args=(delay "$delay" "$jitter")
            [[ "$loss" != "0%" ]] && netem_args+=(loss "$loss")
            [[ "$reorder" != "0%" ]] && netem_args+=(reorder "$reorder")
            for dev_ns in "$NS_SRV:veth-srv" "$NS_CLI:veth-cli"; do
              ns="${dev_ns%%:*}"
              dev="${dev_ns##*:}"
              ip netns exec "$ns" tc qdisc replace dev "$dev" root handle 1: netem "${netem_args[@]}"
              ip netns exec "$ns" tc qdisc replace dev "$dev" parent 1: handle 2: tbf rate "$rate" burst "$burst" latency "$qlat"
            done

            for s in "${SIZE_ARR[@]}"; do
              for ((run_i = 1; run_i <= RUNS; run_i++)); do
                # Concurrent mode: protocols share the bottleneck; label
                # the scenario and record per-protocol rate timelines
                extra_args=()
                run_scenario="$scenario"
                if [[ -n "$PROTO" ]]; then
                  [[ "$PROTO" == *,* ]] && run_scenario+="_conc"
                  extra_args=(-proto="$PROTO" -ratelog="$OUT_DIR/rates_${run_scenario}_${s}mb_r${run_i}.csv")
                fi

                msg_info "Benchmark: ${s} MB @ ${run_scenario} (run ${run_i}/${RUNS})"
                ip netns exec "$NS_CLI" "$SCRIPT_DIR/client/client" \
                  -addr=10.0.0.1 -size="$s" -scenario="$run_scenario" "${extra_args[@]}" \
                  >> "$OUT_DIR/combined.csv" 2>/tmp/qotp_debug.log
              done
            done
          done
        done
      done
    done
  done
done

msg ""
column -t -s, "$OUT_DIR/combined.csv"
msg ""
msg_ok "CSV written to $OUT_DIR/combined.csv"

# Plots are auxiliary: a plotting failure must not fail the benchmark run
# (the CSVs are already written)
if command -v gnuplot &>/dev/null; then
  gnuplot -e "csv='$OUT_DIR/combined.csv'; outdir='$OUT_DIR'" "$SCRIPT_DIR/plot.gp" ||
    msg_info "plot.gp failed for $OUT_DIR/combined.csv (data unaffected)"
  for rcsv in "$OUT_DIR"/rates_*.csv; do
    [[ -e "$rcsv" ]] || continue
    gnuplot -e "csv='$rcsv'; out='${rcsv%.csv}.png'" "$SCRIPT_DIR/plot_rates.gp" ||
      msg_info "plot_rates.gp failed for $rcsv (data unaffected)"
  done
  msg_ok "Plots written to $OUT_DIR/"
else
  msg_info "Install gnuplot to generate charts automatically"
fi
