#!/usr/bin/env python3
"""Turn a qotp-bench JSON result into figures.

    ./plot.py full2.json [outdir]

Writes one PNG per figure plus a combined PDF. Reads only the JSON, so it can
be run anywhere the result file is.
"""
import json
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

COLOR = {"qotp": "#0072B2", "tcp": "#D55E00", "quic": "#009E73"}
DIRS = [("upload", "upload"), ("download", "download")]


def load(path):
    d = json.load(open(path))
    protos = [p for p in ("qotp", "tcp", "quic")
              if any(m["proto"] == p for m in d["measurements"])]
    return d, protos


def rates(d, mode, dir_, proto):
    return [m["mbps"] for m in d["measurements"]
            if m["mode"] == mode and m["dir"] == dir_ and m["proto"] == proto and not m.get("error")]


def med_lo_hi(v):
    return (statistics.median(v), min(v), max(v)) if v else (0, 0, 0)


def fig_throughput(d, protos):
    """Median rate per phase, with the full run-to-run range as the error bar."""
    fig, axes = plt.subplots(2, 2, figsize=(9, 6.5), sharey=True)
    for row, mode in enumerate(("solo", "parallel")):
        for col, (dir_, label) in enumerate(DIRS):
            ax = axes[row][col]
            xs, meds, lo, hi = [], [], [], []
            for i, p in enumerate(protos):
                m, a, b = med_lo_hi(rates(d, mode, dir_, p))
                xs.append(i); meds.append(m); lo.append(m - a); hi.append(b - m)
            ax.bar(xs, meds, color=[COLOR[p] for p in protos], width=0.62,
                   yerr=[lo, hi], capsize=4, ecolor="#444", linewidth=0)
            for i, m in enumerate(meds):
                ax.text(i, m, f"{m:.1f}", ha="center", va="bottom", fontsize=9)
            ax.set_xticks(xs); ax.set_xticklabels(protos)
            ax.set_title(f"{mode} / {label}", fontsize=10)
            ax.grid(axis="y", alpha=0.25, linewidth=0.6)
            ax.set_axisbelow(True)
            if col == 0:
                ax.set_ylabel("Mbps")
    fig.suptitle("Throughput — median of runs, bars span min-max", fontsize=11)
    fig.tight_layout()
    return fig


def fig_fairness(d, protos):
    """Share of the bottleneck under contention, against an equal split."""
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
    fair = 100.0 / len(protos)
    for ax, (dir_, label) in zip(axes, DIRS):
        meds = [med_lo_hi(rates(d, "parallel", dir_, p))[0] for p in protos]
        total = sum(meds) or 1
        share = [100 * m / total for m in meds]
        ax.bar(range(len(protos)), share, color=[COLOR[p] for p in protos],
               width=0.62, linewidth=0)
        ax.axhline(fair, color="#333", linestyle="--", linewidth=1,
                   label=f"equal split ({fair:.1f}%)")
        for i, s in enumerate(share):
            ax.text(i, s, f"{s:.1f}%", ha="center", va="bottom", fontsize=9)
        ax.set_xticks(range(len(protos))); ax.set_xticklabels(protos)
        ax.set_ylim(0, max(share + [fair]) * 1.35)
        ax.set_yticks(range(0, int(max(share + [fair]) * 1.35) + 1, 10))
        ax.set_title(f"parallel / {label}", fontsize=10)
        ax.grid(axis="y", alpha=0.25, linewidth=0.6); ax.set_axisbelow(True)
        ax.legend(fontsize=8, loc="upper right", frameon=False)
    axes[0].set_ylabel("share of bottleneck")
    fig.suptitle("Fairness — three flows sharing one bottleneck", fontsize=11)
    fig.tight_layout()
    return fig


def fig_timeseries(d, protos, phase, title):
    """Rate over time. Line is the median across runs, band is min-max: a wide
    band means the protocol is unstable, not merely slow."""
    fig, ax = plt.subplots(figsize=(9, 3.6))
    step = 0.5
    for p in protos:
        runs = {}
        for s in d["samples"]:
            if s["phase"] == phase and s["proto"] == p:
                runs.setdefault(s["run"], []).append((s["t_seconds"], s["cum_bytes"]))
        series = []
        for pts in runs.values():
            pts.sort()
            out, prev = [], pts[0]
            for t, b in pts[1:]:
                if t - prev[0] >= step:
                    out.append((t, (b - prev[1]) * 8 / 1e6 / (t - prev[0])))
                    prev = (t, b)
            series.append(out)
        if not series:
            continue
        n = min(len(s) for s in series)
        if n == 0:
            continue
        ts = [series[0][i][0] for i in range(n)]
        cols = [[s[i][1] for s in series] for i in range(n)]
        ax.plot(ts, [statistics.median(c) for c in cols], color=COLOR[p], label=p, linewidth=1.6)
        ax.fill_between(ts, [min(c) for c in cols], [max(c) for c in cols],
                        color=COLOR[p], alpha=0.15, linewidth=0)
    ax.set_xlabel("seconds"); ax.set_ylabel("Mbps")
    ax.set_ylim(bottom=0)
    ax.grid(alpha=0.25, linewidth=0.6); ax.set_axisbelow(True)
    ax.legend(fontsize=9, frameon=False)
    ax.set_title(title, fontsize=11)
    fig.tight_layout()
    return fig


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = Path(sys.argv[1])
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "plots")
    out.mkdir(parents=True, exist_ok=True)
    d, protos = load(src)

    figs = [
        ("throughput", fig_throughput(d, protos)),
        ("fairness", fig_fairness(d, protos)),
        ("timeseries-solo-upload",
         fig_timeseries(d, protos, "solo-upload", "solo / upload over time")),
        ("timeseries-parallel-upload",
         fig_timeseries(d, protos, "parallel-upload", "parallel / upload over time")),
        ("timeseries-parallel-download",
         fig_timeseries(d, protos, "parallel-download", "parallel / download over time")),
    ]
    with PdfPages(out / f"{src.stem}.pdf") as pdf:
        for name, fig in figs:
            fig.savefig(out / f"{name}.png", dpi=150)
            pdf.savefig(fig)
            plt.close(fig)
    print(f"wrote {len(figs)} figures + {src.stem}.pdf to {out}/")


if __name__ == "__main__":
    main()
