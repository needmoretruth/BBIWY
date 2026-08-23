//! Profile definitions.
//!
//! **This is the only place transport knowledge lives.** Swapping the Tor
//! implementation, or adding Session Router, should mean editing this table and
//! nothing else; the rest of the code only ever sees a `Transport`.

use crate::out;
use std::path::Path;

/// How a profile reaches the outside.
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
    /// after a warning that says exactly what it leaks.
    Daily,
    /// Nothing persists. Letterboxing enforced.
    Hardened,
}

pub struct Profile {
    pub name: &'static str,
    pub transport: Transport,
    pub strictness: Strictness,
    /// The suffix that only means something on this route.
    pub suffix: Option<&'static str>,
    /// A mark distinct enough to identify a window from one pixel of its edge.
    pub glyph: &'static str,
    /// Whether this route is built yet. Order is native → Tor → I2P → Session.
    pub ready: bool,
}

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "daily",
        transport: Transport::Direct,
        strictness: Strictness::Daily,
        suffix: None,
        glyph: "●",
        ready: true,
    },
    Profile {
        name: "hardened",
        transport: Transport::Direct,
        strictness: Strictness::Hardened,
        suffix: None,
        glyph: "○",
        ready: true,
    },
    Profile {
        name: "tor",
        // C tor for v1. Arti later — and when that happens, this line is the
        // only one that changes.
        transport: Transport::Socks5(9150),
        strictness: Strictness::Hardened,
        suffix: Some(".onion"),
        glyph: "◎",
        ready: false,
    },
    Profile {
        name: "i2p",
        // 4444, not 4447. 4447 is the SOCKS port; the I2P project recommends
        // the HTTP proxy.
        transport: Transport::Http(4444),
        strictness: Strictness::Hardened,
        suffix: Some(".i2p"),
        glyph: "◆",
        ready: false,
    },
    Profile {
        name: "session",
        // Reserved. Upstream has no SOCKS listener at all; the plan is a thin
        // SOCKS5 shim once the embedded TCP tunnel work lands.
        transport: Transport::Socks5(1080),
        strictness: Strictness::Hardened,
        suffix: Some(".sesh"),
        glyph: "⬡",
        ready: false,
    },
];

pub fn find(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

impl Profile {
    /// The one port this profile may reach. `None` means a direct connection,
    /// so ordinary web ports are opened instead.
    pub fn relay_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Direct => None,
            Transport::Socks5(p) | Transport::Http(p) => Some(p),
        }
    }

    /// Turn on the route marking the browser chrome reads.
    ///
    /// The window says which route it is on three ways at once -- a glyph, the
    /// name in letters, and the treatment of its edge -- and all three are
    /// driven from CSS by these preferences. See `theme/bbiwy-path.css`.
    ///
    /// **All five are written, four of them false.** Writing only the true one
    /// would be enough on a fresh profile and wrong on a used one: `prefs.js`
    /// keeps whatever was set before, and a leftover would leave a window
    /// claiming two routes at once. The one accident this browser must never
    /// have is a window that names the wrong route, so the state is stated in
    /// full rather than assumed.
    ///
    /// The block is fenced. Anything else in `user.js` -- the proxy settings,
    /// whatever a lab harness put there -- survives being rewritten.
    pub fn write_route_marking(&self, dir: &Path) -> Result<(), String> {
        const BEGIN: &str = "// >>> bbiwy route -- written at every start";
        const END: &str = "// <<< bbiwy route";

        let path = dir.join("user.js");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();

        let mut kept = String::new();
        let mut inside = false;
        for line in existing.lines() {
            if line == BEGIN {
                inside = true;
            } else if line == END {
                inside = false;
            } else if !inside {
                kept.push_str(line);
                kept.push('\n');
            }
        }

        kept.push_str(BEGIN);
        kept.push('\n');
        for other in PROFILES {
            kept.push_str(&format!(
                "user_pref(\"bbiwy.path.{}\", {});\n",
                other.name,
                other.name == self.name
            ));
        }
        kept.push_str(END);
        kept.push('\n');

        std::fs::write(&path, kept).map_err(|e| format!("could not write {}: {e}", path.display()))
    }

    pub fn route(&self) -> String {
        match self.transport {
            Transport::Direct => "direct".to_string(),
            Transport::Socks5(p) => format!("SOCKS5 {p}"),
            Transport::Http(p) => format!("HTTP proxy {p}"),
        }
    }
}

/// CJK characters occupy two terminal columns. `{:<20}` counts characters, so
/// using it directly misaligns any table containing them.
pub fn pad(s: &str, width: usize) -> String {
    let w: usize = s.chars().map(char_width).sum();
    let mut out = s.to_string();
    for _ in w..width {
        out.push(' ');
    }
    out
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

pub fn list() -> Result<(), String> {
    out::line(&format!(
        "  {} {} {} {}  {}",
        pad("PROFILE", 12),
        pad("ROUTE", 17),
        pad("SUFFIX", 9),
        pad("STATE", 14),
        "MARK"
    ))?;
    out::line("  ────────────────────────────────────────────────────────────")?;
    for p in PROFILES {
        out::line(&format!(
            "  {} {} {} {}  {}",
            pad(p.name, 12),
            pad(&p.route(), 17),
            pad(p.suffix.unwrap_or("—"), 9),
            pad(if p.ready { "ready" } else { "not built yet" }, 14),
            p.glyph
        ))?;
    }
    out::line("")?;
    out::line("All five profiles share one fingerprint. The difference is strictness,")?;
    out::line("not identity.")
}
