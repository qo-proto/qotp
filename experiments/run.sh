#!/usr/bin/env bash

set -Eeuo pipefail
trap 'cleanup $?' SIGINT SIGTERM ERR EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

Run benchmarks locally on loopback (no rate limiting).

OPTIONS:
  -h, --help        Print this help and exit
  --sizes LIST      Comma-separated data sizes in MB (default: 1,4,16,64,128)
  --out DIR         Output directory (default: experiments/results)
EOF
  exit
}

parse_params() {
  SIZES="1,4,16,64,128"
  OUT_DIR="$SCRIPT_DIR/results"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --sizes)
      SIZES="${2-}"
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

mkdir -p "$OUT_DIR"

IFS=',' read -ra SIZE_ARR <<< "$SIZES"

msg_info "Starting server..."
"$SCRIPT_DIR/server/server" >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

echo "protocol,size_mb,total_ms,scenario" > "$OUT_DIR/combined.csv"

for s in "${SIZE_ARR[@]}"; do
  msg_info "Running benchmark: ${s} MB"
  "$SCRIPT_DIR/client/client" -size="$s" -scenario="loopback" \
    >> "$OUT_DIR/combined.csv" 2>/dev/null
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
