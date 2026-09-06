#!/usr/bin/env bash
# Build the specification PDF.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/qotp-spec.typ"
OUT="$SCRIPT_DIR/qotp-spec.pdf"

usage() {
  cat <<USAGE
Usage: $(basename "${BASH_SOURCE[0]}") [--watch]

Compile $(basename "$SRC") to $(basename "$OUT").

OPTIONS:
  --watch     Recompile on every save (live preview while editing)
  -h, --help  Print this help and exit
USAGE
  exit
}

command -v typst >/dev/null || {
  echo "typst not found. Install: https://github.com/typst/typst" >&2
  exit 1
}

case "${1-}" in
  --watch) exec typst watch "$SRC" "$OUT" ;;
  -h|--help) usage ;;
  "") ;;
  *) echo "Unknown option: $1" >&2; exit 1 ;;
esac

typst compile "$SRC" "$OUT"
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
