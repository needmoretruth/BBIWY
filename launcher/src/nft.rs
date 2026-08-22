//! Allow-list generation.
//!
//! The chain policy is `accept` and the last rule drops everything, rather than
//! `policy drop`. That is deliberate: it lets the final rule carry a counter.
//! Without a count there is no way to tell "nothing leaked" apart from "nothing
//! was watching".
//!
//! No `log` statement. `net.netfilter.nf_log_all_netns` defaults to 0, so
//! anything logged from a non-initial network namespace never reaches the host.
//! Counters do.

use crate::profile::Profile;

/// Ports opened for a direct-connection profile. Nothing else, and notably not
/// 53: the browser resolves over DoH, so cleartext DNS is not needed — and an
/// open 53 would be exactly the leak this is meant to prevent.
const DIRECT_PORTS: &[u16] = &[80, 443];

pub fn ruleset(p: &Profile) -> String {
    let mut allow = String::new();
    match p.relay_port() {
        Some(port) => {
            allow.push_str(&format!(
                "    tcp dport {port} counter name allowed accept\n"
            ));
        }
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

    # Loopback always passes. The browser's own internal traffic lives here.
    oifname \"lo\" accept

{allow}
    # IPv6 neighbour discovery is emitted by the kernel, not by the browser.
    # Counted separately so it does not read as a violation.
    icmpv6 type {{ mld-listener-report, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} counter name v6_nd drop

    # Everything else. A non-zero count here means something tried to get out.
    counter name blocked drop
  }}
}}
"
    )
}
