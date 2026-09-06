package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/qo-proto/qotp/experiments/internal/bench"
	quic "github.com/quic-go/quic-go"
)

const probeTimeout = 20 * time.Second

// resolveHost turns a host name into a literal IP. All three protocols then
// target the same address, which matters when a name has several A records.
func resolveHost(h string) (string, error) {
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", h, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("no addresses for %q", h)
}

// preflight checks that all three transports actually reach the responder
// before spending minutes on the measurement. Without it a blocked UDP port
// shows up only as two protocols quietly timing out in every phase, which
// looks like a result rather than a misconfiguration.
func preflight(addr string) {
	var bad []string
	blocked := false
	for _, p := range bench.Protocols {
		if err := probe(p, target(addr, p)); err != nil {
			bad = append(bad, p)
			if looksBlocked(err) {
				blocked = true
			}
			fmt.Fprintf(os.Stderr, "  %-5s %-22s UNREACHABLE: %v\n", p, transportOf(p), err)
		} else {
			fmt.Fprintf(os.Stderr, "  %-5s %-22s ok\n", p, transportOf(p))
		}
	}
	if len(bad) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n%d of 3 transports failed against %s.\n", len(bad), addr)
	if !blocked {
		// Timeouts and refusals point at a firewall; anything else does not,
		// and printing firewall advice for it just sends you the wrong way.
		die("preflight failed")
	}
	fmt.Fprintf(os.Stderr, "The responder needs three ports open, and two protocols:\n")
	for _, p := range bench.Protocols {
		fmt.Fprintf(os.Stderr, "  %s\n", transportOf(p))
	}
	fmt.Fprintf(os.Stderr, "\nCheck on the responder that it is both listening and allowed.\n")
	fmt.Fprintf(os.Stderr, "QUIC working proves UDP reaches the host, so if only qotp fails\n")
	fmt.Fprintf(os.Stderr, "the problem is that port, not UDP in general:\n\n")
	fmt.Fprintf(os.Stderr, "  ss -lnu | grep -E ':(%d|%d)'    # both qotp and quic should appear\n",
		bench.Port(portBase, "qotp"), bench.Port(portBase, "quic"))
	fmt.Fprintf(os.Stderr, "  sudo ufw status | grep -E '%d|%d|%d'\n\n",
		bench.Port(portBase, "qotp"), bench.Port(portBase, "tcp"), bench.Port(portBase, "quic"))
	fmt.Fprintf(os.Stderr, "On the responder:\n")
	for _, p := range bench.Protocols {
		proto, port := "udp", bench.Port(portBase, p)
		if p == "tcp" {
			proto = "tcp"
		}
		fmt.Fprintf(os.Stderr, "  sudo ufw allow %d/%s\n", port, proto)
	}
	fmt.Fprintf(os.Stderr, "\nDo not use \"ufw limit\": it rate-limits new connections and would\n")
	fmt.Fprintf(os.Stderr, "throttle the benchmark itself.\n")
	die("preflight failed")
}

func transportOf(proto string) string {
	t := "UDP"
	if proto == "tcp" {
		t = "TCP"
	}
	return fmt.Sprintf("%s %d", t, bench.Port(portBase, proto))
}

// looksBlocked distinguishes a firewall from a misconfiguration: only a
// timeout or a refusal is evidence about the network.
func looksBlocked(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"timeout", "refused", "no response at all", "unreachable", "no route"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// probe reaches the responder the same way the measurement will, so it fails
// for the same reasons rather than a proxy for them.
func probe(proto, addr string) error {
	switch proto {
	case "tcp":
		c, err := net.DialTimeout("tcp", addr, probeTimeout)
		if err != nil {
			return err
		}
		return c.Close()

	case "quic":
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		// A QUIC handshake needs UDP working in both directions, so completing
		// it is a real reachability test rather than a send that goes nowhere.
		c, err := quic.DialAddr(ctx, addr, bench.ClientTLS(), &quic.Config{MaxIdleTimeout: probeTimeout})
		if err != nil {
			return err
		}
		return c.CloseWithError(0, "")

	default:
		_, err := fetchServerReportTimeout(addr, probeTimeout)
		return err
	}
}
