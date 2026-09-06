# Remote benchmark — two real machines

One binary, no scripts, no root, no traffic shaping. The network between the
two machines is the bottleneck under test.

## Copy one file

`qotp-bench` plays both roles. Build it for the far machine and copy it —
that is the whole deployment. It is built `CGO_ENABLED=0`, so it is static and
needs nothing installed over there:

    cd experiments
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o qotp-bench ./bench/
    scp qotp-bench user@host:

(`GOARCH=arm64` for Apple silicon or a Pi, `GOOS=darwin` for macOS.)

## Run

    # on the far machine
    ./qotp-bench -listen

    # here
    ./qotp-bench -addr <host> -duration 10s -runs 5 -json result.json

That is all. The client prints the whole result: at the end it opens a short
qotp connection, asks the responder for what *it* measured, and folds that into
the same report — so you never have to read two consoles.

## Firewall

Three ports, and **two protocols**. This is the usual reason a run hangs:

| port     | transport | protocol |
|----------|-----------|----------|
| `PORT`   | **UDP**   | qotp     |
| `PORT+1` | **TCP**   | tcp      |
| `PORT+2` | **UDP**   | quic     |

Opening only TCP makes qotp and quic time out while tcp succeeds. Use `-port`
on both sides if 9000-9002 are taken.

The client checks all three before measuring and stops with the exact rules to
add if any are unreachable, so a firewall problem costs a second rather than
several minutes of timeouts.

With **ufw** on the responder, restricted to the one client that needs it:

    sudo ufw allow from CLIENT_IP to any port 9000 proto udp
    sudo ufw allow from CLIENT_IP to any port 9001 proto tcp
    sudo ufw allow from CLIENT_IP to any port 9002 proto udp
    sudo ufw status verbose        # confirm

Afterwards:

    sudo ufw status numbered
    sudo ufw delete <n>            # highest number first

Do **not** use `ufw limit` on these ports: it rate-limits new connections and
would throttle the benchmark itself. Plain `allow` is what you want.

## Shaping the link (optional, but usually necessary)

On a fast path the benchmark measures CPU rather than the protocols. `shape.sh`
caps the three benchmark ports -- and only those -- in both directions, so
everything else on the box, ssh included, is untouched:

    sudo ./shape.sh on 100mbit    # both directions, tcp and udp, ports 9000-9002
    sudo ./shape.sh status        # counters, to confirm traffic is being shaped
    sudo ./shape.sh off

Run it on the responder only; it covers both directions from there. Pick a rate
that leaves CPU headroom -- 100 Mbit is about 8.6k packets a second, well inside
one core for all three stacks, where 1 Gbit is 81k and is not.

It is built for a machine you can only reach over the network:

- **ssh is never shaped.** Only the three benchmark ports match a filter.
  Everything else takes the default class, which is wide open. Measured: with
  shaping on, port 9000 ran at 79 Mbit and port 9500 at 8.6 Gbit on the same
  interface.
- **Nothing touches the live interface until it has worked on a dummy one.**
  The whole configuration is rehearsed on a throwaway device first, so a kernel
  without `ifb` or `act_mirred` fails there rather than against your only route
  in.
- **Any failure unwinds.** A trap tears down everything on error or interrupt,
  so there is no half-applied state.
- **A deadman removes it anyway** after `HOLD` minutes (default 30) unless you
  run `off` first, via `systemd-run` where available. Set `HOLD=60` for a long
  run, or `HOLD=0` to disable it.

Outbound traffic is shaped directly. Inbound cannot be, so matching packets are
redirected to an `ifb` device and shaped on its egress instead. That happens
after the kernel has already received them, so the first round trip of a
transfer is not limited; congestion control settles at the shaped rate within an
RTT or two, which is well inside the warm-up the report discards.

Needs `iproute2` and root, and `DEV=` if the outbound interface is not the one
on the default route.

## Plotting

`-json` writes the full result: every run, every phase, plus a progress sample
every 100ms per flow. `plot.py` turns that into figures without needing the
responder or the network again:

    ./plot.py full.json plots/

Five PNGs and a combined PDF: throughput per phase (median, bars spanning the
run-to-run range), share of the bottleneck against an equal split, and rate
over time for the solo and contended phases. The time-series band is min-max
across runs, so a wide band means unstable rather than merely slow -- which is
what distinguishes a protocol that stalls from one that is simply slower.

Needs matplotlib (`pip install matplotlib`).

## Reading the result

**Check the cpu column first.** Every phase reports cores busy on both sides
*during that phase* — the responder's figure comes back over qotp, so there is
no need to watch `top` there. If a phase says

    !! CPU-bound (responder 1.3 cores for 1 flow(s)): measures per-packet CPU, not the link

then a core was pinned and the numbers rank stacks by cost per packet, not by
protocol behaviour on the path. The test is a core *per flow*, not a busy
machine: qotp runs a whole listener on one goroutine and quic-go a connection
on one, so either can be capped while an 8-core box looks 85% idle. Easy to hit
on a fast link or a small VM — at 1 Gbit with 1500-byte packets that is 81k
packets a second, and with one ack per packet qotp does twice that many
operations, single-threaded.

The fix is not a bigger machine but a slower link: re-run at a rate that leaves
headroom (100 Mbit is ~8.6k pkt/s, comfortably inside one core) and the table
compares protocols again.

**Then check the spread.** `Mbps [min-max]` and the Jain range come from
`-runs`. If the report warns the spread is too wide, the shares are not
comparable however interesting they look. A real path is noisier than a local
link, so prefer `-runs 5` or more.

`vs solo` is the fairness column worth reading: three flows sharing one
bottleneck fairly should each land near 33% of their solo rate.

The **responder section** cross-checks the upload direction. This side can only
approximate delivered bytes for QUIC (it exposes no acked-bytes counter); the
responder counted every byte it actually received. A large disagreement means
the sender-side estimate is off, not that bytes vanished.

## JSON

`-json result.json` writes everything for plotting:

    config          what was asked for
    client, server  core counts and the responder's own totals
    measurements    one row per (run, mode, direction, protocol)
    samples         cumulative bytes over time, tagged with phase and run

Samples carry `phase` and `run` so a time series can be drawn per phase instead
of every phase overlapping.
