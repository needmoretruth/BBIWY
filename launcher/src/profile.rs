//! Profile definitions.
//!
//! **This is the only place transport knowledge lives.** Swapping the Tor
//! implementation, or adding Session Router, should mean editing this table and
//! nothing else; the rest of the code only ever sees a `Transport`, or the
//! `Relay` it resolves to once the installed ports are known.

use crate::out::{self, pad};
use std::fmt;

/// How a profile reaches the outside, with the port the table assumes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// Straight out. No proxy.
    Direct,
    /// SOCKS5 proxy on this local port.
    Socks5(u16),
    /// HTTP proxy on this local port.
    Http(u16),
}

/// How strict a profile is. Note this is *not* a fingerprint setting:
/// all five profiles share one fingerprint. Keeping logins, history and
/// autofill was measured to cost zero fingerprint difference, so there is no
/// reason to split the anonymity set over convenience.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strictness {
    /// Logins and history persist. Letterboxing is on, but can be turned off
    /// — it is the one relaxation that costs fingerprint uniformity.
    Daily,
    /// Nothing persists. Letterboxing enforced.
    Hardened,
}

/// A proxied route as installed: the protocol, and the port on the host's
/// loopback it is carried to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Relay {
    Socks5(u16),
    Http(u16),
}

impl Relay {
    pub fn port(self) -> u16 {
        match self {
            Relay::Socks5(p) | Relay::Http(p) => p,
        }
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relay::Socks5(p) => write!(f, "SOCKS5 127.0.0.1:{p}"),
            Relay::Http(p) => write!(f, "HTTP 127.0.0.1:{p}"),
        }
    }
}

pub struct Profile {
    pub name: &'static str,
    /// The name as a menu shows it.
    pub title: &'static str,
    /// One line for the menu entry: where it goes, and what it keeps.
    pub about: &'static str,
    pub transport: Transport,
    pub strictness: Strictness,
    /// The suffix that only means something on this route.
    pub suffix: Option<&'static str>,
    /// The route mark: the same glyph `theme/bbiwy-path.css` draws in front of
    /// the route name in the address bar.
    pub glyph: &'static str,
    /// What has to be running on the host for the route to reach anything.
    pub daemon: Option<&'static str>,
    /// How to get that daemon going, for the message shown when it is not.
    pub hint: &'static str,
    /// Other ports that daemon commonly listens on. If the configured port is
    /// silent but one of these answers, the message says so.
    pub usual_ports: &'static [u16],
    /// Whether this route is built yet. Order is native → Tor → I2P → Session.
    pub ready: bool,
}

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "daily",
        title: "Daily",
        about: "Direct connection. Logins and history are kept.",
        transport: Transport::Direct,
        strictness: Strictness::Daily,
        suffix: None,
        glyph: "⬤",
        daemon: None,
        hint: "",
        usual_ports: &[],
        ready: true,
    },
    Profile {
        name: "hardened",
        title: "Hardened",
        about: "Direct connection. Nothing is kept.",
        transport: Transport::Direct,
        strictness: Strictness::Hardened,
        suffix: None,
        glyph: "◯",
        daemon: None,
        hint: "",
        usual_ports: &[],
        ready: true,
    },
    Profile {
        name: "tor",
        title: "Tor",
        about: "Over Tor, with .onion. Nothing is kept.",
        // C tor for v1. Arti later — and when that happens, this line is the
        // only one that changes. 9150 is Tor Browser's port and Arti's default;
        // a system tor listens on 9050 (`bbiwy install --tor-port 9050`).
        transport: Transport::Socks5(9150),
        strictness: Strictness::Hardened,
        suffix: Some(".onion"),
        glyph: "◎",
        daemon: Some("tor"),
        hint: "Start tor — for a system tor, `sudo systemctl start tor`.",
        usual_ports: &[9050, 9150],
        ready: true,
    },
    Profile {
        name: "i2p",
        title: "I2P",
        about: "Over I2P, with .i2p. Nothing is kept.",
        // 4444, not 4447. 4447 is the SOCKS port; the I2P project recommends
        // the HTTP proxy. i2pd and Java I2P both default to 4444.
        transport: Transport::Http(4444),
        strictness: Strictness::Hardened,
        suffix: Some(".i2p"),
        glyph: "◆",
        daemon: Some("I2P router"),
        hint: "Start your I2P router (i2pd or Java I2P); its HTTP proxy is what this route uses.",
        usual_ports: &[4444],
        ready: true,
    },
    Profile {
        name: "session",
        title: "Session",
        about: "Session Router internal services. Nothing is kept.",
        // Reserved. Upstream has no SOCKS listener at all; the plan is a thin
        // SOCKS5 shim once the embedded TCP tunnel work lands.
        transport: Transport::Socks5(1080),
        strictness: Strictness::Hardened,
        suffix: Some(".sesh"),
        glyph: "⬡",
        daemon: Some("Session Router"),
        hint: "",
        usual_ports: &[],
        ready: false,
    },
];

pub fn find(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

/// Names of the routes that can be started today, for messages.
pub fn ready_names() -> String {
    PROFILES
        .iter()
        .filter(|p| p.ready)
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Relay ports chosen at install time. A route absent here uses the table's
/// port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ports(Vec<(&'static str, u16)>);

impl Ports {
    pub fn get(&self, name: &str) -> Option<u16> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
    }

    /// Sets the port of a proxied route. A direct route has no relay to move.
    pub fn set(&mut self, name: &str, port: u16) -> Result<(), String> {
        let p = find(name).ok_or_else(|| format!("unknown profile: {name}"))?;
        if p.transport == Transport::Direct {
            return Err(format!("the {name} route is direct; it has no relay port."));
        }
        if port == 0 {
            return Err("port 0 is not a port.".into());
        }
        self.0.retain(|(n, _)| *n != p.name);
        self.0.push((p.name, port));
        self.0
            .sort_by_key(|(n, _)| PROFILES.iter().position(|q| q.name == *n));
        Ok(())
    }

    /// The routes whose port was set, with that port.
    pub fn iter_pairs(&self) -> impl Iterator<Item = (&'static str, u16)> + '_ {
        self.0.iter().copied()
    }

    /// Every proxied route with the relay it will actually use, in table order.
    pub fn resolved(&self) -> Vec<(&'static str, Relay)> {
        PROFILES
            .iter()
            .filter_map(|p| p.relay(self).map(|r| (p.name, r)))
            .collect()
    }

    /// The same set with every proxied route's port written out, so that the
    /// record says what is in effect rather than what was left at a default.
    pub fn explicit(&self) -> Ports {
        let mut all = Ports::default();
        for (name, relay) in self.resolved() {
            all.0.push((name, relay.port()));
        }
        all
    }
}

impl Profile {
    /// The relay this profile uses once installed, or `None` for a direct one.
    pub fn relay(&self, ports: &Ports) -> Option<Relay> {
        match self.transport {
            Transport::Direct => None,
            Transport::Socks5(d) => Some(Relay::Socks5(ports.get(self.name).unwrap_or(d))),
            Transport::Http(d) => Some(Relay::Http(ports.get(self.name).unwrap_or(d))),
        }
    }

    pub fn route(&self, ports: &Ports) -> String {
        match self.relay(ports) {
            None => "direct".to_string(),
            Some(r) => r.to_string(),
        }
    }

    pub fn strictness_name(&self) -> &'static str {
        match self.strictness {
            Strictness::Daily => "daily",
            Strictness::Hardened => "hardened",
        }
    }
}

pub fn list() -> Result<(), String> {
    let stamp = crate::browser::locate()
        .ok()
        .and_then(|i| i.stamp().ok().flatten());
    let ports = stamp.as_ref().map(|s| s.ports.clone()).unwrap_or_default();

    out::line(&format!(
        "  {} {} {} {}  {}",
        pad("PROFILE", 10),
        pad("ROUTE", 23),
        pad("SUFFIX", 8),
        pad("STATE", 24),
        "MARK"
    ))?;
    out::line(&format!("  {}", "─".repeat(72)))?;
    for p in PROFILES {
        let state = if crate::status::running(p.name).is_some() {
            "running".to_string()
        } else if !p.ready {
            "not built yet".to_string()
        } else {
            match p.relay(&ports) {
                Some(r) if !crate::sys::tcp_listener(r.port()).is_some_and(|l| l.takes_v4()) => {
                    format!("{} not running", p.daemon.unwrap_or("relay"))
                }
                _ => "ready".to_string(),
            }
        };
        out::line(&format!(
            "  {} {} {} {}  {}",
            pad(p.name, 10),
            pad(&p.route(&ports), 23),
            pad(p.suffix.unwrap_or("—"), 8),
            pad(&state, 24),
            p.glyph
        ))?;
    }
    out::line("")?;
    if stamp.is_none() {
        out::line("Not installed yet, so the ports above are the defaults. Run `bbiwy install`.")?;
    }
    out::line("All five profiles share one fingerprint. The difference is strictness,")?;
    out::line("not identity.")
}
