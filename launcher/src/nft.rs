//! 화이트리스트 생성.
//!
//! 정책은 `accept` 로 두고 **마지막 줄에서 전부 떨어뜨린다.** `policy drop` 이 아니라
//! 이렇게 하는 이유는 **떨어진 것을 세기 위해서**다. 세지 않으면 「안 샜다」와
//! 「보고 있지 않았다」를 구별할 수 없다.
//!
//! ⚠ `log` 를 쓰지 않는다. `net.netfilter.nf_log_all_netns` 가 기본 0 이라
//! 비초기 network namespace 에서 찍은 로그는 호스트로 가지 않는다. 계수기는 간다.

use crate::profile::Profile;

/// 직접 연결 프로필에서 여는 포트. 그 밖은 전부 막힌다.
const DIRECT_PORTS: &[u16] = &[80, 443];

pub fn ruleset(p: &Profile) -> String {
    let mut allow = String::new();
    match p.relay_port() {
        // 경로가 있는 프로필: 그 포트 하나만 연다.
        Some(port) => {
            allow.push_str(&format!(
                "    tcp dport {port} counter name allowed accept\n"
            ));
        }
        // 직접 연결: 일반 웹 포트만 연다. DNS(53)조차 열지 않는다 —
        // 브라우저가 프록시 없이도 DoH 로 나가게 해 두면 평문 DNS 는 필요 없고,
        // 열어 두면 그게 곧 누수 통로가 된다.
        None => {
            for port in DIRECT_PORTS {
                allow.push_str(&format!(
                    "    tcp dport {port} counter name allowed accept\n"
                ));
            }
        }
    }

    format!(
        "table inet bbiwy {{
  counter allowed {{}}
  counter blocked {{}}
  counter v6_nd {{}}

  chain out {{
    type filter hook output priority 0; policy accept;

    # 자기 자신은 언제나 통과. 브라우저 내부 통신이 여기 있다.
    oifname \"lo\" accept

{allow}
    # IPv6 이웃탐색은 커널이 알아서 내는 것이라 위반이 아니다. 따로 센다.
    icmpv6 type {{ mld-listener-report, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} counter name v6_nd drop

    # 나머지 전부. 이 계수기가 0 이 아니면 무언가 새려고 했다는 뜻이다.
    counter name blocked drop
  }}
}}
"
    )
}
