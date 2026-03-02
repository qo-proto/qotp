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

# ── Helper: extract per-protocol data into a temp file ───────────────────────
# Columns: size_mb  total_ms  throughput_mbps
extract(proto, scen, tmpf) = system(sprintf( \
    "awk -F, 'NR>1 && $1==\"%s\" && $4==\"%s\" { printf \"%%s %%s %%s\\n\", $2, $3, ($2*8*1000)/$3 }' '%s' | sort -n > '%s'", \
    proto, scen, csv, tmpf))

# ── Chart 1: Dual-axis per scenario ─────────────────────────────────────────
# Left Y-axis:  Transfer Time (ms)   — dashed lines
# Right Y-axis: Throughput (Mbps)    — solid lines

do for [sc in scenarios] {
    tmp_tcp   = sprintf("%s/_tcp.dat",   outdir)
    tmp_qotp  = sprintf("%s/_qotp.dat",  outdir)
    tmp_http3 = sprintf("%s/_http3.dat",  outdir)

    dummy = extract("tcp",   sc, tmp_tcp)
    dummy = extract("qotp",  sc, tmp_qotp)
    dummy = extract("http3", sc, tmp_http3)

    outfile = sprintf("%s/bench_%s.png", outdir, sc)
    set terminal pngcairo size 900,550 font "sans,11" enhanced
    set output outfile

    set title sprintf("Benchmark: %s", sc)
    set xlabel "Data Size (MB)"
    set ylabel "Transfer Time (ms)"
    set y2label "Throughput (Mbps)"

    set ytics nomirror
    set y2tics
    set grid xtics ytics

    set key top left box opaque

    # Solid lines for throughput
    set style line 1 lc rgb tcp_color   lw 2 pt 7 ps 1.2
    set style line 2 lc rgb qotp_color  lw 2 pt 5 ps 1.2
    set style line 3 lc rgb http3_color lw 2 pt 9 ps 1.2
    # Dashed lines for time
    set style line 4 lc rgb tcp_color   lw 2 pt 7 ps 1.2 dt 3
    set style line 5 lc rgb qotp_color  lw 2 pt 5 ps 1.2 dt 3
    set style line 6 lc rgb http3_color lw 2 pt 9 ps 1.2 dt 3

    set datafile separator " "

    plot \
        tmp_tcp   using 1:3 axes x1y2 title "TCP throughput"    with linespoints ls 1, \
        tmp_qotp  using 1:3 axes x1y2 title "QOTP throughput"   with linespoints ls 2, \
        tmp_http3 using 1:3 axes x1y2 title "HTTP/3 throughput"  with linespoints ls 3, \
        tmp_tcp   using 1:2 axes x1y1 title "TCP time"    with linespoints ls 4, \
        tmp_qotp  using 1:2 axes x1y1 title "QOTP time"   with linespoints ls 5, \
        tmp_http3 using 1:2 axes x1y1 title "HTTP/3 time"  with linespoints ls 6

    unset output
    print sprintf("wrote %s", outfile)

    system(sprintf("rm -f '%s' '%s' '%s'", tmp_tcp, tmp_qotp, tmp_http3))
}

# ── Chart 2: Scenario comparison (grouped bars at largest size) ──────────────
# Only if there are multiple scenarios

num_scenarios = words(scenarios)
if (num_scenarios > 1) {

    # Find the largest size in the CSV
    max_size = system(sprintf("awk -F, 'NR>1{print $2}' '%s' | sort -n | tail -1", csv))

    # Extract throughput values into a temp file for bar plotting:
    #   scenario tcp_tp qotp_tp http3_tp
    tmpfile = sprintf("%s/_comparison.dat", outdir)
    system(sprintf( \
        "awk -F, 'NR>1 && $2==%s { tp=($2*8*1000)/$3; data[$4][$1]=tp } " \
        "END { for(s in data) printf \"%%s %%s %%s %%s\\n\", s, " \
        "(\"tcp\" in data[s] ? data[s][\"tcp\"] : 0), " \
        "(\"qotp\" in data[s] ? data[s][\"qotp\"] : 0), " \
        "(\"http3\" in data[s] ? data[s][\"http3\"] : 0) }' '%s' | sort > '%s'", \
        max_size, csv, tmpfile))

    outfile = sprintf("%s/comparison.png", outdir)
    set terminal pngcairo size 900,550 font "sans,11" enhanced
    set output outfile

    set title sprintf("Throughput Comparison at %s MB", max_size)
    set ylabel "Throughput (Mbps)"
    unset y2label
    unset y2tics
    set ytics mirror

    set style data histogram
    set style histogram clustered gap 1
    set style fill solid 0.8 border -1
    set boxwidth 0.9

    set datafile separator " "
    set grid ytics
    set key top right box opaque
    set xtics rotate by -30

    plot \
        tmpfile using 2:xtic(1) title "TCP"   lc rgb tcp_color, \
        tmpfile using 3         title "QOTP"  lc rgb qotp_color, \
        tmpfile using 4         title "HTTP/3" lc rgb http3_color

    unset output
    print sprintf("wrote %s", outfile)

    system(sprintf("rm -f '%s'", tmpfile))
}
