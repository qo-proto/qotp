# Per-protocol rate timeline for a concurrent run — invoked by run_netns.sh
#
# Usage:
#   gnuplot -e "csv='results/rates_<scenario>_<size>mb.csv'; out='rates.png'" plot_rates.gp
#
# CSV format: protocol,t_s,mbps,cum_mb

if (!exists("csv")) csv = "rates.csv"
if (!exists("out")) out = "rates.png"

tcp_color   = "#1f77b4"
qotp_color  = "#ff7f0e"
http3_color = "#2ca02c"

# Extract one protocol's samples into a temp file: t_s mbps.
# No printf/%%-escaping in the awk program: nested format strings proved
# fragile across sprintf/shell layers (a suite run under sudo produced a
# corrupted format string); plain print is escape-proof.
extract(proto, tmpf) = system(sprintf( \
    "awk -F, -v p='%s' '$1==p { print $2, $3 }' '%s' > '%s'", \
    proto, csv, tmpf))

tmp_tcp   = out . "_tcp.dat"
tmp_qotp  = out . "_qotp.dat"
tmp_http3 = out . "_http3.dat"
dummy = extract("tcp",   tmp_tcp)
dummy = extract("qotp",  tmp_qotp)
dummy = extract("http3", tmp_http3)

set terminal pngcairo size 1000,550 font "sans,11" enhanced
set output out

set title "Throughput over time (concurrent flows, shared bottleneck)" noenhanced
set xlabel "Time (s)"
set ylabel "Rate (Mbit/s)"
set grid xtics ytics
set key top right box opaque
set yrange [0:*]
set datafile separator " "

set style line 1 lc rgb tcp_color   lw 2
set style line 2 lc rgb qotp_color  lw 2
set style line 3 lc rgb http3_color lw 2

# Protocols without samples produce empty files; gnuplot skips them with a
# warning, which is fine
plot \
    tmp_tcp   using 1:2 title "TCP"    with lines ls 1, \
    tmp_qotp  using 1:2 title "QOTP"   with lines ls 2, \
    tmp_http3 using 1:2 title "HTTP/3" with lines ls 3

unset output
print sprintf("wrote %s", out)

system(sprintf("rm -f '%s' '%s' '%s'", tmp_tcp, tmp_qotp, tmp_http3))
