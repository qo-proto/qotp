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
  -h, --help      Print this help and exit
  --size MB       Data size in MB (default: 32)
  --out DIR       Output directory (default: experiments/results)
EOF
  exit
}

parse_params() {
  SIZE=32
  OUT_DIR="$SCRIPT_DIR/results"

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    --size)
      SIZE="${2-}"
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

msg_info "Starting server..."
"$SCRIPT_DIR/server/server" >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

msg_info "Running benchmark: ${SIZE} MB"
msg ""

"$SCRIPT_DIR/client/client" -size="$SIZE" -out="$OUT_DIR/combined.csv" 2>/dev/null
column -t -s, "$OUT_DIR/combined.csv"
msg ""
msg_ok "CSV written to $OUT_DIR/combined.csv"
