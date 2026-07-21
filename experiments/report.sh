#!/usr/bin/env bash

# Summarize a suite run (see suite.sh): solo completion-time ratios and
# concurrent fairness (Jain index over the window where all flows are
# active). Writes the report to <dir>/summary.txt and stdout.
#
# Usage: ./report.sh <suite-out-dir>

set -Eeuo pipefail

DIR="${1-}"
[[ -d "$DIR" ]] || { echo "usage: $0 <suite-out-dir>" >&2; exit 1; }

report() {

echo "SUITE REPORT — $(basename "$DIR")"
echo

# ── Solo scenarios ───────────────────────────────────────────────────────────
echo "SOLO (sequential; ratio = qotp time / other's time; lower is faster)"
printf "%-20s %9s %9s %9s %8s %8s  %s\n" \
  scenario tcp_ms qotp_ms http3_ms "q/tcp" "q/h3" verdict

for d in "$DIR"/solo_*/; do
  [[ -e "$d/combined.csv" ]] || continue
  name=$(basename "$d")
  awk -F, -v name="$name" 'NR>1 { t[$1]=$3 }
  END {
    qt = (t["tcp"]   > 0) ? t["qotp"]/t["tcp"]   : 0
    qh = (t["http3"] > 0) ? t["qotp"]/t["http3"] : 0
    verdict = "OK"
    if (qt > 2.0 && qh > 2.0)      verdict = "FAIL (qotp >2x slower than both)"
    else if (qt > 2.0 || qh > 2.0) verdict = "WARN (qotp >2x slower than one)"
    else if (qt < 0.5 && qh < 0.5) verdict = "NOTE (qotp >2x faster than both)"
    printf "%-20s %9.0f %9.0f %9.0f %8.2f %8.2f  %s\n",
      name, t["tcp"], t["qotp"], t["http3"], qt, qh, verdict
  }' "$d/combined.csv"
done

echo
# ── Fairness scenarios ───────────────────────────────────────────────────────
echo "FAIRNESS (concurrent; mean Mbit/s while ALL flows active, t >= 1s;"
echo "          Jain index: 1.0 = perfectly fair, 1/n = one flow hogging)"
printf "%-20s %8s %8s %8s %6s  %s\n" scenario tcp qotp http3 jain verdict

for d in "$DIR"/fair*/; do
  [[ -d "$d" ]] || continue
  name=$(basename "$d")
  rcsv=$(ls "$d"/rates_*.csv 2>/dev/null | head -1)
  [[ -n "$rcsv" ]] || continue
  awk -F, -v name="$name" '
  NR>1 {
    if (!( $1 in last ) || $2 > last[$1]) last[$1] = $2
    ts[$1 "_" $2] = $3
    protos[$1] = 1
  }
  END {
    # overlap window: until the first flow finishes
    overlap = 1e18
    n = 0
    for (p in protos) { n++; if (last[p] < overlap) overlap = last[p] }
    if (n == 0 || overlap <= 1.0) {
      printf "%-20s  no overlap data\n", name
    } else {
      sum = 0; sumsq = 0
      # stable order for display
      split("tcp qotp http3", ORDER, " ")
      for (i = 1; i <= 3; i++) {
        p = ORDER[i]
        if (!(p in protos)) { disp[p] = -1; continue }
        s = 0; c = 0
        for (t = 1.0; t <= overlap + 0.001; t += 0.1) {
          key = p "_" sprintf("%.1f", t)
          if (key in ts) { s += ts[key]; c++ }
        }
        m = (c > 0) ? s / c : 0
        disp[p] = m
        sum += m; sumsq += m * m
      }
      jain = (sumsq > 0) ? (sum * sum) / (n * sumsq) : 0
      verdict = "PASS"
      if (jain < 0.60)      verdict = "FAIL (one flow dominates)"
      else if (jain < 0.75) verdict = "WARN"
      printf "%-20s %8.1f %8.1f %8.1f %6.2f  %s\n",
        name, disp["tcp"], disp["qotp"], disp["http3"], jain, verdict
    }
  }' "$rcsv"
done

echo
echo "(-1.0 = protocol not part of this scenario)"
}

report | tee "$DIR/summary.txt"
