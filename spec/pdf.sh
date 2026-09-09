#!/usr/bin/env bash
# Build the specification PDF.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS=(qotp-spec qotp-why)

usage() {
  cat <<USAGE
Usage: $(basename "${BASH_SOURCE[0]}") [--watch]

Compile qotp-spec.typ and qotp-why.typ to PDF.

OPTIONS:
  --watch     Recompile qotp-spec.typ on every save (live preview)
  -h, --help  Print this help and exit
USAGE
  exit
}

command -v typst >/dev/null || {
  echo "typst not found. Install: https://github.com/typst/typst" >&2
  exit 1
}

case "${1-}" in
  --watch) exec typst watch "$SCRIPT_DIR/qotp-spec.typ" "$SCRIPT_DIR/qotp-spec.pdf" ;;
  -h|--help) usage ;;
  "") ;;
  *) echo "Unknown option: $1" >&2; exit 1 ;;
esac

for doc in "${DOCS[@]}"; do
  typst compile "$SCRIPT_DIR/$doc.typ" "$SCRIPT_DIR/$doc.pdf"
  echo "wrote $doc.pdf ($(du -h "$SCRIPT_DIR/$doc.pdf" | cut -f1))"
done
