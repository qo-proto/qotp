#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building benchmarks..."
for dir in "$SCRIPT_DIR"/bench_*/; do
    if [[ -f "$dir/main.go" ]]; then
        name=$(basename "$dir")
        echo "Building $name..."
        go build -o "$dir$name" "$dir/main.go"
        echo "  Built: $dir$name"
    fi
done
echo "Done."
