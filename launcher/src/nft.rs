//! Allow-list generation.
//!
//! The chain policy is `accept` and the last rules drop everything, rather than
//! `policy drop`. That is deliberate: it lets every drop carry a counter.
//! Without a count there is no way to tell "nothing leaked" apart from "nothing
//! was watching". What was dropped is counted by kind, so that a number in
//! `bbiwy status` also says *what* tried to get out.
//!
//! No `log` statement. `net.netfilter.nf_log_all_netns` defaults to 0, so
//! anything logged from a non-initial network namespace never reaches the host.
//! Counters do.
//!
//! Loopback inside the namespace holds nothing from the host except what pasta
//! was told to carry (`pasta.rs`): the relay port on a proxied profile, nothing
//! at all on a direct one. The relay is matched — and counted — before the rule
//! that lets the browser's own internal loopback traffic through.

use crate::profile::Relay;

/// Ports opened for a direct-connection profile. Nothing else, and notably not
/// 53: the browser resolves over DNS-over-HTTPS, reaching its resolver by
/// address (`prefs.rs`), so cleartext DNS is never needed — and an open 53
/// would be exactly the leak this is meant to prevent.
const DIRECT_PORTS: &str = "{ 80, 443 }";

/// The counters that mean something was stopped, with the word `bbiwy status`
/// shows for each. (`udp` and `tcp` themselves are nft keywords, so they cannot
/// be counter names.) `allowed` counts the route itself; `v6_nd` counts the
/// kernel's own IPv6 housekeeping.
pub const BLOCKED: &[(&str, &str)] = &[
    ("dns", "dns"),
    ("udp_other", "udp"),
    ("tcp_other", "tcp"),
    ("other", "other"),
];

pub fn ruleset(relay: Option<Relay>) -> String {
    let allow = match relay {
        Some(r) => format!(
            "    # The relay. pasta carries this one port to the host's loopback, and
    # nothing else; every other address and port is dropped below.
    oifname \"lo\" tcp dport {port} counter name allowed accept

    # The rest of loopback stays inside the namespace: the browser talking to
    # itself.
    oifname \"lo\" accept
",
            port = r.port()
        ),
        None => format!(
            "    # Loopback stays inside the namespace; nothing from the host is on it.
    oifname \"lo\" accept

    tcp dport {DIRECT_PORTS} counter name allowed accept
"
        ),
    };

    format!(
        "table inet bbiwy {{
  counter allowed {{}}
  counter dns {{}}
  counter udp_other {{}}
  counter tcp_other {{}}
  counter other {{}}
  counter v6_nd {{}}

  chain out {{
    type filter hook output priority 0; policy accept;

{allow}
    # IPv6 neighbour discovery and MLD are emitted by the kernel bringing the
    # link up, not by the browser. Counted separately so they do not read as
    # violations.
    icmpv6 type {{ mld-listener-report, mld-listener-done, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} counter name v6_nd drop

    # Everything else. A non-zero count here means something tried to get out.
    udp dport 53 counter name dns drop
    tcp dport 53 counter name dns drop
    meta l4proto udp counter name udp_other drop
    meta l4proto tcp counter name tcp_other drop
    counter name other drop
  }}
}}
"
    )
}
