# Local benchmark — one machine

Two modes:

    ./run.sh                    # loopback, no bottleneck
    sudo ./run.sh --netns       # rate-limited link between two namespaces

**Loopback has no bottleneck.** Solo throughput is meaningful there (it shows
per-packet efficiency); fairness is not, because nothing is contended. The
report says so.

`--netns` builds a veth pair between two network namespaces and shapes **both**
directions with netem — asymmetric shaping silently makes the reverse path the
limit. The bottleneck queue defaults to one bandwidth-delay product computed
from `--rate`/`--delay`; netem's own default (1000 packets) is several BDP of
drop-tail buffer, which bufferbloats the link and makes fairness swing wildly
between runs.

    sudo ./run.sh --netns --rate 100mbit --delay 10ms --duration 10s --runs 5
    sudo ./run.sh --netns --rate 1gbit --delay 50ms --queue 4000

Both modes drive the same `qotp-bench` binary; `run.sh` exists only because
`--netns` needs root and `tc`. For two real machines no script is needed at
all — see `../remote`.
