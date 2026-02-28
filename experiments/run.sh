#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIZE=${1:-33554432}  # 32MB default
OUT_DIR="${2:-$SCRIPT_DIR/results}"

mkdir -p "$OUT_DIR"

"$SCRIPT_DIR/bench/bench" -size="$SIZE" -out="$OUT_DIR/combined.csv" 2>/dev/null
column -t -s, "$OUT_DIR/combined.csv"
echo ""
echo "CSV written to $OUT_DIR/combined.csv"
