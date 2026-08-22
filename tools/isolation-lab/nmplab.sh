#!/usr/bin/env bash
# nmplab — NMP 격리 실험대.
#
# 하나의 브라우저 프로필을 network namespace 안에 가두고, 거기서 나가려는 모든
# 패킷을 화이트리스트로 판정한다. 허용은 단 하나 — 지정한 릴레이 포트로 가는 TCP.
# 그 외 전부 위반으로 세고, 기록하고, 버린다.
#
# 이 하네스가 브라우저 pref보다 아래층에 있다는 점이 핵심이다. pref를 우회하는
# 구성요소(uBO의 browser.dns.resolve 같은 것)도 여기서는 못 빠져나간다.
#
#   nmplab.sh up   <이름> <릴레이포트> [--observe]
#                                       격리망 생성. --observe 는 막지 않고 세기만 한다 —
#                                       브라우저 설정 층이 혼자 얼마나 버티는지 재는 용도.
#   nmplab.sh run  <이름> -- <명령...>   격리망 안에서 실행 (호출한 사용자 권한 유지)
#   nmplab.sh reset <이름>              계수기 초기화
#   nmplab.sh verdict <이름>            위반 계수 출력. 0이면 종료코드 0
#   nmplab.sh down <이름>               정리
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${NMPLAB_STATE:-/run/nmplab}"

need_root() { [[ $EUID -eq 0 ]] || exec sudo -E NMPLAB_STATE="$STATE_DIR" "$0" "$@"; }

# 이름에서 결정론적으로 /30 서브넷 하나를 뽑는다. 실험대를 여러 개 동시에 띄우기 위함.
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

  ip netns list | grep -qx "$ns" && { echo "이미 존재: $ns" >&2; exit 1; }
  mkdir -p "$STATE_DIR" "/etc/netns/$ns"

  # 시스템 리졸버를 그대로 두면 netns 안 lo로 빠져 위반이 안 잡힌다.
  # 바깥 주소를 넣어야 "DNS를 쏘려 했다"가 veth에서 계수된다.
  if [[ "$mode" == "--observe" ]]; then
    # 관찰 모드 — 막지 않고 세기만 한다. 브라우저 설정 층이 혼자 얼마나 버티는지
    # 재려면 아래층을 걷어내야 한다. 실제 리졸버를 주고 밖으로도 내보낸다.
    # 호스트의 리졸버가 127.0.0.53(systemd-resolved) 같은 루프백이면 격리망에서
    # 도달할 수 없다. 관찰 모드에서는 실제로 나가는 리졸버를 준다.
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

  # 호스트 방화벽(ufw 등)이 기본 DROP이면 실험대에서 오는 허용 트래픽까지 막는다.
  # 실험대 veth에서 오는 것만 최상단에서 통과시킨다. down에서 되돌린다.
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

  # 화이트리스트. 정책은 accept가 아니라 "허용 한 줄 뒤 전부 계수 후 drop"이다.
  # 종류별로 나눠 세는 이유: 위반이 났을 때 무엇이 샜는지 바로 알기 위함.
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
    # 커널이 veth를 올릴 때 내는 IPv6 이웃탐색·MLD는 브라우저가 낸 것이 아니다.
    # 따로 세어 두되 위반으로 치지 않는다. 섞으면 진짜 누수가 잡음에 묻힌다.
    icmpv6 type { mld-listener-report, mld-listener-done, nd-router-solicit, \
                  nd-neighbor-solicit, nd-neighbor-advert } counter name v6_nd drop
    meta l4proto { icmp, icmpv6 } counter name icmp_any log prefix "NMPLEAK icmp " drop
    meta l4proto tcp counter name tcp_other log prefix "NMPLEAK tcp " $verdict_action
    counter name tcp_other log prefix "NMPLEAK other " $verdict_action
  }
}
NFT

  echo "$relay" > "$STATE_DIR/$name.relay"
  echo "격리망 준비됨: ns=$ns  안=$nip  밖=$hip  허용=tcp://$hip:$relay  방식=${mode/--/}"
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
  echo "계수기 초기화: $(ns_name "$name")"
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
print("%-10s %8s %10s" % ("계수기","패킷","바이트"))
for c in rows:
    print("%-10s %8d %10d" % (c["name"], c["packets"], c["bytes"]))
    if c["name"]=="allowed": allowed=c["packets"]
    elif c["name"]=="v6_nd": pass          # 커널 잡음. 위반이 아니다.
    else: viol+=c["packets"]
print()
nd=[c["packets"] for c in rows if c["name"]=="v6_nd"]
print("허용 경로 패킷: %d" % allowed)
if nd and nd[0]: print("커널 IPv6 잡음: %d (위반 아님)" % nd[0])
print("위반 패킷:      %d" % viol)
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
  echo "정리됨: $ns"
}

case "${1:-}" in
  up)      shift; cmd_up "$@" ;;
  reset)   shift; cmd_reset "$@" ;;
  run)     shift; cmd_run "$@" ;;
  verdict) shift; cmd_verdict "$@" ;;
  down)    shift; cmd_down "$@" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
