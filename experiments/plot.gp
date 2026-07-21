# Benchmark visualization — invoked by run.sh / run_netns.sh
#
# Usage:
#   gnuplot -e "csv='results/combined.csv'; outdir='results'" plot.gp
#
# CSV format: protocol,size_mb,total_ms,scenario

if (!exists("csv"))    csv    = "results/combined.csv"
if (!exists("outdir")) outdir = "results"

# ── Colors & styles ──────────────────────────────────────────────────────────
tcp_color   = "#1f77b4"
qotp_color  = "#ff7f0e"
http3_color = "#2ca02c"

# ── Discover unique scenarios from column 4 (skip header) ───────────────────
scenarios = system(sprintf("awk -F, 'NR>1{print $4}' '%s' | sort -u", csv))
num_sizes = int(system(sprintf("awk -F, 'NR>1{print $2}' '%s' | sort -nu | wc -l", csv)))

# ── Helper: extract per-protocol data into a temp file ───────────────────────
# Aggregates repeated runs: columns are size_mb, mean total_ms, stddev.
# No printf in the awk (format strings are fragile across escape layers).
extract(proto, scen, tmpf) = system(sprintf( \
    "awk -F, -v p='%s' -v s='%s' '$1==p && $4==s { n[$2]++; su[$2]+=$3; sq[$2]+=$3*$3 } " . \
    "END { for (k in n) { m = su[k]/n[k]; " . \
    "sd = (n[k] > 1) ? sqrt((sq[k] - su[k]*su[k]/n[k]) / (n[k]-1)) : 0; " . \
    "print k, m, sd } }' '%s' | sort -n > '%s'", \
    proto, scen, csv, tmpf))

# ── Chart 1: Transfer time vs data size, per scenario ───────────────────────
# Needs at least two sizes: with a single size these would be one-point
# "lines" — the scenario comparison chart below covers that case instead.
# Implemented by emptying the loop list (gnuplot cannot nest an if-block
# around a do-for block).
chart1_scenarios = (num_sizes > 1) ? scenarios : ""

do for [sc in chart1_scenarios] {
    tmp_tcp   = sprintf("%s/_tcp.dat",   outdir)
    tmp_qotp  = sprintf("%s/_qotp.dat",  outdir)
    tmp_http3 = sprintf("%s/_http3.dat",  outdir)

    dummy = extract("tcp",   sc, tmp_tcp)
    dummy = extract("qotp",  sc, tmp_qotp)
    dummy = extract("http3", sc, tmp_http3)

    outfile = sprintf("%s/bench_%s.png", outdir, sc)
    set terminal pngcairo size 900,550 font "sans,11" enhanced
    set output outfile

    set title sprintf("Benchmark: %s", sc) noenhanced
    set xlabel "Data Size (MB)"
    set ylabel "Transfer Time (ms)"

    # Sizes and times both span orders of magnitude (1..64 MB) — log-log
    # keeps small sizes readable and makes linear scaling show as a
    # straight line
    set logscale x 2
    set logscale y 10
    set grid xtics ytics

    set key top left box opaque

    set style line 1 lc rgb tcp_color   lw 2 pt 7 ps 1.2
    set style line 2 lc rgb qotp_color  lw 2 pt 5 ps 1.2
    set style line 3 lc rgb http3_color lw 2 pt 9 ps 1.2

    set datafile separator " "

    plot \
        tmp_tcp   using 1:2:3 title "TCP"    with yerrorlines ls 1, \
        tmp_qotp  using 1:2:3 title "QOTP"   with yerrorlines ls 2, \
        tmp_http3 using 1:2:3 title "HTTP/3" with yerrorlines ls 3

    unset output
    print sprintf("wrote %s", outfile)

    unset logscale

    system(sprintf("rm -f '%s' '%s' '%s'", tmp_tcp, tmp_qotp, tmp_http3))
}

# ── Chart 2: Scenario comparison (grouped bars at largest size) ──────────────
# Only if there are multiple scenarios

num_scenarios = words(scenarios)
if (num_scenarios > 1) {

    # Find the largest size in the CSV
    max_size = system(sprintf("awk -F, 'NR>1{print $2}' '%s' | sort -n | tail -1", csv))

    # Extract transfer times into a temp file for bar plotting, aggregating
    # repeated runs: scenario tcp_mean tcp_sd qotp_mean qotp_sd h3_mean h3_sd
    # (no printf in the awk: format strings are fragile across escape layers)
    tmpfile = sprintf("%s/_comparison.dat", outdir)
    system(sprintf( \
        "awk -F, -v ms='%s' 'NR>1 && $2==ms { k=$4 SUBSEP $1; n[k]++; su[k]+=$3; sq[k]+=$3*$3; seen[$4]=1 } " . \
        "END { split(\"tcp qotp http3\", P, \" \"); " . \
        "for (s in seen) { line = s; " . \
        "for (i = 1; i <= 3; i++) { k = s SUBSEP P[i]; " . \
        "if (n[k] > 0) { m = su[k]/n[k]; sd = (n[k] > 1) ? sqrt((sq[k] - su[k]*su[k]/n[k]) / (n[k]-1)) : 0 } " . \
        "else { m = 0; sd = 0 } " . \
        "line = line \" \" m \" \" sd }; " . \
        "print line } }' '%s' | sort > '%s'", \
        max_size, csv, tmpfile))

    outfile = sprintf("%s/comparison.png", outdir)
    set terminal pngcairo size 900,550 font "sans,11" enhanced
    set output outfile

    set title sprintf("Transfer Time Comparison at %s MB", max_size)
    set xlabel "Scenario"
    set ylabel "Transfer Time (ms)"

    set style data histogram
    set style histogram errorbars gap 1 lw 1
    set style fill solid 0.8 border -1
    set boxwidth 0.9

    set datafile separator " "
    set grid ytics
    set key top right box opaque
    set xtics rotate by -30 noenhanced

    plot \
        tmpfile using 2:3:xtic(1) title "TCP"    lc rgb tcp_color, \
        tmpfile using 4:5         title "QOTP"   lc rgb qotp_color, \
        tmpfile using 6:7         title "HTTP/3" lc rgb http3_color

    unset output
    print sprintf("wrote %s", outfile)

    system(sprintf("rm -f '%s'", tmpfile))
}
