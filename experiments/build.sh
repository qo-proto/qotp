#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building benchmark..."
go build -o "$SCRIPT_DIR/bench/bench" "$SCRIPT_DIR/bench/main.go"
echo "Done."
