#!/usr/bin/env bash

# Summarize a suite run (see suite.sh): solo completion-time ratios and
# concurrent fairness (Jain index over the window where all flows are
# active). Repeated measurements (--runs) are aggregated as mean±sd.
# Writes the report to <dir>/summary.txt and stdout.
#
# Usage: ./report.sh <suite-out-dir>

set -Eeuo pipefail

DIR="${1-}"
[[ -d "$DIR" ]] || { echo "usage: $0 <suite-out-dir>" >&2; exit 1; }

# Per-run fairness numbers from one rates CSV: "tcp qotp http3 jain"
# (protocol absent from the run -> -1). Empty output if no overlap window.
fairness_of() {
  awk -F, '
  NR>1 {
    if (!( $1 in last ) || $2 > last[$1]) last[$1] = $2
    ts[$1 "_" $2] = $3
    protos[$1] = 1
  }
  END {
    overlap = 1e18
    n = 0
    for (p in protos) { n++; if (last[p] < overlap) overlap = last[p] }
    if (n == 0 || overlap <= 1.0) exit
    sum = 0; sumsq = 0
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
    print disp["tcp"], disp["qotp"], disp["http3"], jain
  }' "$1"
}

report() {

echo "SUITE REPORT — $(basename "$DIR")"
echo

# ── Solo scenarios ───────────────────────────────────────────────────────────
echo "SOLO (sequential; mean±sd over runs; ratio = qotp mean / other's mean)"
printf "%-20s %13s %13s %13s %6s %6s  %s\n" \
  scenario tcp_ms qotp_ms http3_ms "q/tcp" "q/h3" verdict

for d in "$DIR"/solo_*/; do
  [[ -e "$d/combined.csv" ]] || continue
  name=$(basename "$d")
  awk -F, -v name="$name" 'NR>1 { n[$1]++; su[$1]+=$3; sq[$1]+=$3*$3 }
  END {
    for (p in n) {
      m[p] = su[p]/n[p]
      sd[p] = (n[p] > 1) ? sqrt((sq[p] - su[p]*su[p]/n[p]) / (n[p]-1)) : 0
    }
    qt = (m["tcp"]   > 0) ? m["qotp"]/m["tcp"]   : 0
    qh = (m["http3"] > 0) ? m["qotp"]/m["http3"] : 0
    verdict = "OK"
    if (qt > 2.0 && qh > 2.0)      verdict = "FAIL (qotp >2x slower than both)"
    else if (qt > 2.0 || qh > 2.0) verdict = "WARN (qotp >2x slower than one)"
    else if (qt < 0.5 && qh < 0.5) verdict = "NOTE (qotp >2x faster than both)"
    printf "%-20s %7.0f±%-5.0f %7.0f±%-5.0f %7.0f±%-5.0f %6.2f %6.2f  %s\n",
      name, m["tcp"], sd["tcp"], m["qotp"], sd["qotp"],
      m["http3"], sd["http3"], qt, qh, verdict
  }' "$d/combined.csv"
done

echo
# ── Fairness scenarios ───────────────────────────────────────────────────────
echo "FAIRNESS (concurrent; mean Mbit/s while ALL flows active, t >= 1s;"
echo "          mean±sd over runs; Jain: 1.0 = fair, 1/n = one flow hogging)"
printf "%-20s %8s %8s %8s %11s  %s\n" scenario tcp qotp http3 jain verdict

for d in "$DIR"/fair*/; do
  [[ -d "$d" ]] || continue
  name=$(basename "$d")
  runs=""
  for rcsv in "$d"/rates_*.csv; do
    [[ -e "$rcsv" ]] || continue
    runs+="$(fairness_of "$rcsv")"$'\n'
  done
  [[ -n "${runs//[$'\n' ]/}" ]] || continue
  echo "$runs" | awk -v name="$name" 'NF == 4 {
    n++
    for (i = 1; i <= 4; i++) { su[i] += $i; sq[i] += $i * $i }
  }
  END {
    if (n == 0) { printf "%-20s  no overlap data\n", name; exit }
    for (i = 1; i <= 4; i++) {
      m[i] = su[i] / n
      sd[i] = (n > 1) ? sqrt((sq[i] - su[i]*su[i]/n) / (n-1)) : 0
    }
    verdict = "PASS"
    if (m[4] < 0.60)      verdict = "FAIL (one flow dominates)"
    else if (m[4] < 0.75) verdict = "WARN"
    printf "%-20s %8.1f %8.1f %8.1f %5.2f±%-4.2f  %s\n",
      name, m[1], m[2], m[3], m[4], sd[4], verdict
  }'
done

echo
echo "(-1.0 = protocol not part of this scenario)"
}

report | tee "$DIR/summary.txt"
