#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIZE=${1:-33554432}  # 32MB default
OUT_DIR="${2:-$SCRIPT_DIR/results}"

mkdir -p "$OUT_DIR"

echo "Benchmark: $SIZE bytes per protocol"
echo ""

cleanup() {
    kill $SRV_PID 2>/dev/null
    wait $SRV_PID 2>/dev/null
}
trap cleanup EXIT

# --- TCP ---
echo "=== TCP ==="
"$SCRIPT_DIR/bench_tcp/bench_tcp" -mode=server &
SRV_PID=$!
sleep 0.5
"$SCRIPT_DIR/bench_tcp/bench_tcp" -mode=client -size="$SIZE" -out="$OUT_DIR/tcp.csv"
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
echo ""

# --- QOTP ---
echo "=== QOTP ==="
"$SCRIPT_DIR/bench_qotp/bench_qotp" -mode=server 2>/dev/null &
SRV_PID=$!
sleep 0.5
"$SCRIPT_DIR/bench_qotp/bench_qotp" -mode=client -size="$SIZE" -out="$OUT_DIR/qotp.csv" 2>/dev/null
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
echo ""

# --- HTTP/3 ---
echo "=== HTTP/3 ==="
"$SCRIPT_DIR/bench_http3/bench_http3" -mode=server 2>/dev/null &
SRV_PID=$!
sleep 0.5
"$SCRIPT_DIR/bench_http3/bench_http3" -mode=client -size="$SIZE" -out="$OUT_DIR/http3.csv" 2>/dev/null
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
echo ""

# --- Combine results ---
echo "=== Results ==="
echo "protocol,size_bytes,send_ms,total_ms" > "$OUT_DIR/combined.csv"
for f in "$OUT_DIR"/tcp.csv "$OUT_DIR"/qotp.csv "$OUT_DIR"/http3.csv; do
    tail -1 "$f" >> "$OUT_DIR/combined.csv"
done

column -t -s, "$OUT_DIR/combined.csv"
echo ""
echo "CSV written to $OUT_DIR/combined.csv"
