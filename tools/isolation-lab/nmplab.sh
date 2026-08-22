#!/usr/bin/env bash
# nmplab — the isolation lab.
#
# Confines one browser profile to a network namespace and judges every packet
# that tries to leave against an allow-list. Exactly one thing passes: TCP to
# the nominated relay port. Everything else is counted as a violation and dropped.
#
# The point is that this sits *below* the browser's preferences. A component
# that bypasses those preferences still cannot get out through here.
#
#   nmplab.sh up   <name> <relay-port> [--observe]
#                                       create the namespace. --observe counts
#                                       without blocking, to measure how far the
#                                       preference layer holds up on its own.
#   nmplab.sh run  <name> -- <cmd...>    run inside, as the calling user
#   nmplab.sh reset <name>               zero the counters
#   nmplab.sh verdict <name>             print violations; exit 0 if there were none
#   nmplab.sh down <name>                tear down
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${NMPLAB_STATE:-/run/nmplab}"

need_root() { [[ $EUID -eq 0 ]] || exec sudo -E NMPLAB_STATE="$STATE_DIR" "$0" "$@"; }

# Derive a /30 deterministically from the name, so several labs can coexist.
subnet_octet() { printf '%d' "$(( 0x$(printf '%s' "$1" | md5sum | cut -c1-2) % 250 + 2 ))"; }

ns_name()   { echo "nmp-$1"; }
host_ip()   { echo "10.77.$(subnet_octet "$1").1"; }
ns_ip()     { echo "10.77.$(subnet_octet "$1").2"; }
veth_host() { echo "nmph$(subnet_octet "$1")"; }
veth_ns()   { echo "nmpn$(subnet_octet "$1")"; }

cmd_up() {
  local name="$1" relay="$2" mode="${3:-enforce}"
  need_root up "$name" "$relay" "$mode"
  local ns hip nip vh vn
  ns=$(ns_name "$name"); hip=$(host_ip "$name"); nip=$(ns_ip "$name")
  vh=$(veth_host "$name"); vn=$(veth_ns "$name")

  ip netns list | grep -qx "$ns" && { echo "already exists: $ns" >&2; exit 1; }
  mkdir -p "$STATE_DIR" "/etc/netns/$ns"

  # Leaving the system resolver in place sends DNS to loopback inside the
  # namespace, where nothing counts it. Point it outward so an attempt is seen.
  if [[ "$mode" == "--observe" ]]; then
    # Observe mode: count, do not block. To measure the preference layer alone,
    # the layer beneath it has to be taken away.
    # A loopback resolver (systemd-resolved on 127.0.0.53) is unreachable from
    # inside, so observe mode hands over one that actually leaves the machine.
    echo "nameserver ${NMPLAB_OBSERVE_DNS:-9.9.9.9}" > "/etc/netns/$ns/resolv.conf"
  else
    echo "nameserver ${NMPLAB_DNS:-9.9.9.9}" > "/etc/netns/$ns/resolv.conf"
  fi

  ip netns add "$ns"
  ip link add "$vh" type veth peer name "$vn"
  ip link set "$vn" netns "$ns"
  ip addr add "$hip/30" dev "$vh"
  ip link set "$vh" up
  ip -n "$ns" addr add "$nip/30" dev "$vn"
  ip -n "$ns" link set "$vn" up
  ip -n "$ns" link set lo up
  ip -n "$ns" route add default via "$hip"

  # A host firewall defaulting to DROP will also block the lab's permitted
  # traffic. Accept from the lab veth at the top; `down` undoes this.
  iptables -I INPUT 1 -i "$vh" -j ACCEPT 2>/dev/null || true

  local verdict_action="drop"
  if [[ "$mode" == "--observe" ]]; then
    verdict_action="accept"
    sysctl -qw net.ipv4.ip_forward=1
    iptables -t nat -C POSTROUTING -s "$nip/32" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "$nip/32" -j MASQUERADE
    iptables -I FORWARD 1 -i "$vh" -j ACCEPT
    iptables -I FORWARD 1 -o "$vh" -j ACCEPT
  fi

  # The allow-list. Policy stays accept so the final rule can carry a counter:
  # counting by kind is what tells you *what* leaked, not merely that something did.
  ip netns exec "$ns" nft -f - <<NFT
table inet nmplab {
  counter dns_udp   {}
  counter dns_tcp   {}
  counter quic_udp  {}
  counter other_udp {}
  counter tcp_other {}
  counter icmp_any  {}
  counter v6_nd     {}
  counter allowed   {}
  chain out {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    ip daddr $hip tcp dport $relay counter name allowed accept
    udp dport 53 counter name dns_udp log prefix "NMPLEAK dns/udp " $verdict_action
    tcp dport 53 counter name dns_tcp log prefix "NMPLEAK dns/tcp " $verdict_action
    udp dport 443 counter name quic_udp log prefix "NMPLEAK quic " $verdict_action
    meta l4proto udp counter name other_udp log prefix "NMPLEAK udp " $verdict_action
    # IPv6 neighbour discovery and MLD come from the kernel bringing the link up,
    # not from the browser. Counted separately, or real leaks drown in noise.
    icmpv6 type { mld-listener-report, mld-listener-done, nd-router-solicit, \
                  nd-neighbor-solicit, nd-neighbor-advert } counter name v6_nd drop
    meta l4proto { icmp, icmpv6 } counter name icmp_any log prefix "NMPLEAK icmp " drop
    meta l4proto tcp counter name tcp_other log prefix "NMPLEAK tcp " $verdict_action
    counter name tcp_other log prefix "NMPLEAK other " $verdict_action
  }
}
NFT

  echo "$relay" > "$STATE_DIR/$name.relay"
  echo "namespace ready: ns=$ns  inside=$nip  outside=$hip  allowed=tcp://$hip:$relay  mode=${mode/--/}"
}

cmd_run() {
  local name="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  local ns; ns=$(ns_name "$name")
  local uid=${SUDO_UID:-$(id -u)} gid=${SUDO_GID:-$(id -g)}
  need_root run "$name" -- "$@"
  uid=${SUDO_UID:-$uid}; gid=${SUDO_GID:-$gid}
  exec ip netns exec "$ns" setpriv --reuid="$uid" --regid="$gid" --clear-groups \
       env HOME="$(getent passwd "$uid" | cut -d: -f6)" \
           DISPLAY="${DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-}" \
           PATH="$PATH" NMPLAB_NS="$ns" "$@"
}

cmd_reset() {
  local name="$1"
  need_root reset "$name"
  ip netns exec "$(ns_name "$name")" nft reset counters table inet nmplab >/dev/null
  echo "counters zeroed: $(ns_name "$name")"
}

cmd_verdict() {
  local name="$1"
  need_root verdict "$name"
  local ns; ns=$(ns_name "$name")
  local json total=0
  json=$(ip netns exec "$ns" nft -j list counters table inet nmplab)
  echo "$json" | python3 -c '
import json,sys
d=json.load(sys.stdin)
rows=[o["counter"] for o in d["nftables"] if "counter" in o]
allowed=0; viol=0
print("%-10s %8s %10s" % ("counter","packets","bytes"))
for c in rows:
    print("%-10s %8d %10d" % (c["name"], c["packets"], c["bytes"]))
    if c["name"]=="allowed": allowed=c["packets"]
    elif c["name"]=="v6_nd": pass          # kernel noise, not a violation
    else: viol+=c["packets"]
print()
nd=[c["packets"] for c in rows if c["name"]=="v6_nd"]
print("packets on the allowed route: %d" % allowed)
if nd and nd[0]: print("kernel IPv6 noise:  %d (not a violation)" % nd[0])
print("violating packets:  %d" % viol)
sys.exit(1 if viol else 0)
'
}

cmd_down() {
  local name="$1"
  need_root down "$name"
  local ns vh; ns=$(ns_name "$name"); vh=$(veth_host "$name")
  iptables -t nat -D POSTROUTING -s "$(ns_ip "$name")/32" -j MASQUERADE 2>/dev/null || true
  while iptables -C FORWARD -i "$vh" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$vh" -j ACCEPT; done
  while iptables -C FORWARD -o "$vh" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$vh" -j ACCEPT; done
  ip netns del "$ns" 2>/dev/null || true
  while iptables -C INPUT -i "$vh" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -i "$vh" -j ACCEPT
  done
  ip link del "$vh" 2>/dev/null || true
  rm -rf "/etc/netns/$ns" "$STATE_DIR/$name.relay"
  echo "torn down: $ns"
}

case "${1:-}" in
  up)      shift; cmd_up "$@" ;;
  reset)   shift; cmd_reset "$@" ;;
  run)     shift; cmd_run "$@" ;;
  verdict) shift; cmd_verdict "$@" ;;
  down)    shift; cmd_down "$@" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
