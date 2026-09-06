#!/usr/bin/env bash
# Rate-limit the benchmark ports in both directions, and nothing else.
#
#   sudo ./shape.sh on 100mbit     shape qotp/tcp/quic to 100 Mbit each way
#   sudo ./shape.sh off            remove it
#   ./shape.sh status              counters, to confirm traffic is being shaped
#
# Written for a machine you can only reach over the network. Three properties
# matter more here than concision:
#
#   1. ssh is never shaped. Only the benchmark ports match a filter; everything
#      else takes the default class, which is wide open.
#   2. Nothing is applied to the live interface until the whole configuration
#      has been rehearsed on a throwaway device. A kernel missing ifb or
#      act_mirred fails against the dummy, not against your only route in.
#   3. If any step still fails, the trap tears the whole thing down, and a
#      deadman timer removes it anyway after HOLD minutes.
#
# Outbound is shaped directly. Inbound cannot be, so matching packets are
# redirected to an ifb device and shaped on its egress instead.
set -euo pipefail

PORT=${PORT:-9000}      # 9000 & 0xfffc covers 9000-9003, so one filter catches
MASK=0xfffc             # qotp, tcp and quic. The port sits at the same offset
                        # in the tcp and udp headers, so it matches both.
IFB=${IFB:-ifb0}
HOLD=${HOLD:-30}        # minutes before the deadman removes shaping; 0 disables
DEV=${DEV:-$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')}
SELF=$(readlink -f "$0")
CHK=shapechk0

[ -n "$DEV" ] || { echo "cannot detect the outbound interface; set DEV=" >&2; exit 1; }

down() {
  tc qdisc del dev "$DEV" root    2>/dev/null || true
  tc qdisc del dev "$DEV" ingress 2>/dev/null || true
  tc qdisc del dev "$IFB" root    2>/dev/null || true
  ip link del "$IFB"              2>/dev/null || true
}

# apply installs the full configuration on $1. Used twice: once against a dummy
# device to prove the kernel supports it, then against the real interface.
apply() {
  local dev=$1 rate=$2
  tc qdisc add dev "$dev" root handle 1: htb default 99
  tc class add dev "$dev" parent 1: classid 1:99 htb rate 10gbit ceil 10gbit quantum 200000
  tc class add dev "$dev" parent 1: classid 1:10 htb rate "$rate" ceil "$rate" quantum 60000
  tc qdisc add dev "$dev" parent 1:10 handle 10: fq_codel
  tc filter add dev "$dev" protocol ip parent 1: prio 1 u32 \
     match ip sport "$PORT" $MASK flowid 1:10

  tc qdisc add dev "$dev" handle ffff: ingress
  tc filter add dev "$dev" parent ffff: protocol ip prio 1 u32 \
     match ip dport "$PORT" $MASK \
     action mirred egress redirect dev "$IFB"
}

rehearse() {
  local rate=$1
  ip link del "$CHK" 2>/dev/null || true
  ip link add "$CHK" type dummy
  ip link set "$CHK" up
  # Any failure here is the kernel's, and costs nothing: the real interface has
  # not been touched yet.
  if ! apply "$CHK" "$rate" 2>/tmp/shape-rehearsal.$$; then
    echo "this kernel cannot do the shaping; nothing was changed on $DEV:" >&2
    sed 's/^/  /' /tmp/shape-rehearsal.$$ >&2
    ip link del "$CHK" 2>/dev/null || true
    rm -f /tmp/shape-rehearsal.$$
    down
    exit 1
  fi
  rm -f /tmp/shape-rehearsal.$$
  ip link del "$CHK"
}

# arm schedules an unconditional removal. If shaping ever costs you access, or
# you simply walk away, the machine returns to normal on its own.
arm() {
  disarm
  [ "$HOLD" -gt 0 ] || { echo "deadman disabled (HOLD=0): remember to run '$SELF off'"; return; }
  if command -v systemd-run >/dev/null 2>&1 &&
     systemd-run --quiet --unit=shape-revert --on-active="${HOLD}min" \
                 "$SELF" off >/dev/null 2>&1; then
    echo "deadman armed: shaping is removed in ${HOLD}min unless you run '$SELF off' first"
  else
    setsid nohup sh -c "sleep $((HOLD * 60)); '$SELF' off" >/dev/null 2>&1 &
    { echo $! >/run/shape-revert.pid; } 2>/dev/null || true
    echo "deadman armed (background): shaping is removed in ${HOLD}min"
  fi
}

disarm() {
  systemctl stop shape-revert.timer 2>/dev/null || true
  systemctl reset-failed shape-revert.service 2>/dev/null || true
  [ -f /run/shape-revert.pid ] && { kill "$(cat /run/shape-revert.pid)" 2>/dev/null || true; rm -f /run/shape-revert.pid; }
  return 0
}

case "${1:-status}" in
off)
  disarm
  down
  echo "shaping removed from $DEV"
  ;;

on)
  RATE=${2:-100mbit}
  [ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
  down
  modprobe ifb numifbs=0 2>/dev/null || true
  ip link add "$IFB" type ifb
  ip link set "$IFB" up

  rehearse "$RATE"

  # From here the live interface is being modified. Any failure, including a
  # signal, unwinds everything rather than leaving half a configuration.
  trap 'echo "failed partway; reverting $DEV" >&2; down; exit 1' ERR INT TERM

  apply "$DEV" "$RATE"
  tc qdisc add dev "$IFB" root handle 1: htb default 10
  tc class add dev "$IFB" parent 1: classid 1:10 htb rate "$RATE" ceil "$RATE" quantum 60000
  tc qdisc add dev "$IFB" parent 1:10 handle 10: fq_codel

  trap - ERR INT TERM
  echo "$DEV: ports $PORT-$((PORT + 3)) tcp+udp shaped to $RATE each direction"
  arm
  ;;

status)
  echo "== $DEV egress (this host -> peer) =="
  tc -s class show dev "$DEV" 2>/dev/null | grep -A2 'htb 1:10' || echo "  not shaped"
  echo "== $IFB (peer -> this host) =="
  tc -s class show dev "$IFB" 2>/dev/null | grep -A2 'htb 1:10' || echo "  not shaped"
  ;;

*) echo "usage: $0 {on [rate]|off|status}   (HOLD=minutes, DEV=iface, PORT=base)" >&2; exit 1 ;;
esac
