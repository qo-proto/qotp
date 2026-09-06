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

## Reading the result

**Check both CPU lines first.** The report gives cores busy on this side per
phase, and on the responder for the whole session. If either says

    !! CPU-bound: ... this measures per-packet CPU cost, not the link

then the machine, not the path, was the limit and the numbers say nothing about
the protocols. Easy to hit on a fast link or a small VM.

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
