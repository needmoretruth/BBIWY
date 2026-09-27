//! `bbiwy doctor` — does isolation actually hold on this machine?
//!
//! This exists because the failure mode that matters is not a crash. It is a
//! browser that starts normally on a machine where isolation silently does not
//! work, leaving someone believing they are protected when they are not.

use std::ffi::OsStr;
use std::process::Stdio;

use crate::apparmor::{self, Coverage};
use crate::browser::{self, Drift};
use crate::out::{self, pad};
use crate::profile::{Ports, PROFILES};
use crate::{pasta, sys};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Isolation cannot be established without this.
    Fatal,
    /// Something will not work, but nothing will run unprotected because of it.
    Warn,
}

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    pub level: Level,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>, level: Level) -> Check {
    Check { name, ok, detail: detail.into(), level }
}

pub fn checks() -> Vec<Check> {
    let mut out = Vec::new();

    for (bin, name, why) in [
        ("pasta", "pasta (passt)", "attaches the namespace to the network"),
        ("nft", "nftables", "installs the allow-list"),
        ("setpriv", "setpriv (util-linux)", "drops capabilities before the browser starts"),
    ] {
        let found = sys::tool(bin);
        out.push(check(
            name,
            found.is_some(),
            match &found {
                Some(p) => format!("{} — {why}", p.display()),
                None => format!("not found. Needed: it {why}"),
            },
            Level::Fatal,
        ));
    }

    let missing: Vec<&str> = ["curl", "gpg", "tar", "xz", "zip", "unzip"]
        .into_iter()
        .filter(|b| sys::tool(b).is_none())
        .collect();
    out.push(check(
        "install tools",
        missing.is_empty(),
        if missing.is_empty() {
            "curl, gpg, tar, xz, zip, unzip — used only by `bbiwy install`".to_string()
        } else {
            format!("missing: {} — `bbiwy install` needs them", missing.join(", "))
        },
        Level::Warn,
    ));
    let nsenter = sys::tool("nsenter").is_some();
    out.push(check(
        "nsenter",
        nsenter,
        if nsenter {
            "reads the counters for `bbiwy status`"
        } else {
            "not found — `bbiwy status` cannot read the counters without it"
        },
        Level::Warn,
    ));

    // Unprivileged user namespaces. Off entirely on some kernels; restricted by
    // default on Ubuntu 23.10+, where an AppArmor profile is what lifts it.
    let disabled = sys::sysctl("user.max_user_namespaces").as_deref() == Some("0")
        || sys::sysctl("kernel.unprivileged_userns_clone").as_deref() == Some("0");
    let (ok, detail) = if disabled {
        (false, "disabled by the kernel (user.max_user_namespaces or kernel.unprivileged_userns_clone is 0)".to_string())
    } else {
        match apparmor::coverage() {
            Coverage::NotNeeded => (true, "allowed".to_string()),
            Coverage::Ours => (true, "AppArmor restricts them; the BBIWY profile lets pasta through".to_string()),
            Coverage::Distro(what) => (true, format!("AppArmor restricts them; the distribution's profile ({what}) lets pasta through")),
            Coverage::Missing => (
                false,
                "AppArmor blocks them and nothing lets pasta through. Run: sudo bbiwy apparmor".to_string(),
            ),
        }
    };
    out.push(check("user namespaces", ok, detail, Level::Fatal));

    // The browser, and whether BBIWY's files in it are current.
    let mut ports = Ports::default();
    match browser::locate() {
        Err(e) => out.push(check("browser", false, e, Level::Warn)),
        Ok(inst) => match inst.check() {
            Err(e) => out.push(check("browser", false, e.replace("\n  ", " "), Level::Warn)),
            Ok((stamp, drift)) => {
                ports = stamp.ports.clone();
                let base = format!("Mullvad Browser {} in {}", inst.version(), inst.dir.display());
                if drift.is_empty() {
                    out.push(check("browser", true, format!("{base} — locks and theme current"), Level::Warn));
                } else {
                    let mut what = Vec::new();
                    if drift.contains(&Drift::Locks) {
                        what.push("the locks are not the ones this launcher writes");
                    }
                    if drift.contains(&Drift::Theme) {
                        what.push("omni.ja changed (a browser update?) and the theme is gone");
                    }
                    out.push(check(
                        "browser",
                        false,
                        format!("{base} — {}. `bbiwy run` repairs this before starting, or run `bbiwy install`", what.join("; ")),
                        Level::Warn,
                    ));
                }
            }
        },
    }

    // The daemons behind the proxied routes.
    for p in PROFILES.iter().filter(|p| p.ready) {
        let Some(r) = p.relay(&ports) else {
            continue;
        };
        let daemon = p.daemon.unwrap_or("relay");
        let up = sys::tcp_listener(r.port()).is_some_and(|l| l.takes_v4());
        let mut detail = if up {
            format!("{daemon} is listening on 127.0.0.1:{}", r.port())
        } else {
            format!("nothing on 127.0.0.1:{} — start {daemon} to use this route", r.port())
        };
        if !up {
            for other in p.usual_ports.iter().filter(|o| **o != r.port()) {
                if sys::tcp_listener(*other).is_some_and(|l| l.takes_v4()) {
                    detail.push_str(&format!(
                        " (something is on {other}: `bbiwy install --{}-port {other}`)",
                        p.name
                    ));
                }
            }
        }
        let name: &'static str = match p.name {
            "tor" => "route: tor",
            "i2p" => "route: i2p",
            "session" => "route: session",
            _ => "route",
        };
        out.push(check(name, up, detail, Level::Warn));
    }

    // The namespace cannot touch the display layer. Under X11 any client can
    // read any other client's input and screen, so profiles are not isolated
    // from each other even though their traffic is.
    let (grade, detail) = display_grade();
    out.push(check("profile-to-profile", grade != Grade::None, detail, Level::Warn));

    out
}

#[derive(PartialEq, Eq)]
pub enum Grade {
    /// The compositor keeps clients apart.
    Full,
    /// Mostly kept apart, with known gaps.
    Partial,
    /// Not kept apart at all.
    None,
}

fn display_grade() -> (Grade, String) {
    let wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let d = desktop.to_ascii_lowercase();

    if !wayland {
        return (
            Grade::None,
            "X11 — profiles can read each other's keystrokes and screens. \
             Network isolation is unaffected"
                .into(),
        );
    }
    if d.contains("gnome") {
        (
            Grade::None,
            "Wayland (GNOME) — GNOME does not implement the client isolation \
             protocol yet, so profiles can still observe each other"
                .into(),
        )
    } else if d.contains("kde") || d.contains("plasma") {
        (
            Grade::Partial,
            "Wayland (KDE) — mostly isolated, but the clipboard is shared".into(),
        )
    } else {
        (
            Grade::Full,
            format!(
                "Wayland ({}) — profiles cannot observe each other",
                if desktop.is_empty() { "wlroots-family" } else { &desktop }
            ),
        )
    }
}

pub fn doctor() -> Result<(), String> {
    out::line("BBIWY preflight")?;
    out::line("")?;
    let cs = checks();
    let mut fatal_failed = false;
    for c in &cs {
        let mark = match (c.ok, c.level) {
            (true, _) => "OK  ",
            (false, Level::Fatal) => "FAIL",
            (false, Level::Warn) => "WARN",
        };
        out::line(&format!("  {mark}  {} {}", pad(c.name, 20), c.detail))?;
        if !c.ok && c.level == Level::Fatal {
            fatal_failed = true;
        }
    }
    out::line("")?;
    if fatal_failed {
        out::line("Isolation cannot be established. Fix the FAIL lines above first.")?;
        return Err("preflight failed".into());
    }
    if sys::euid() == Some(0) {
        out::line("Running as root, so the namespace was not built for real: pasta would drop")?;
        out::line("to `nobody`. Run `bbiwy doctor` as the user who browses.")?;
        return Ok(());
    }

    // Having the parts is not the same as the parts working together. Build a
    // namespace exactly as `run` does, and inside it load the allow-list and
    // try to remove it after the capability drop.
    let pasta_bin = sys::tool("pasta").ok_or("pasta disappeared")?;
    let me = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    let o = pasta::command(&pasta_bin, None, &me, &[OsStr::new("__probe")])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run pasta: {e}"))?;
    if o.status.success() {
        out::line("Built a namespace exactly as `bbiwy run` does, loaded the allow-list in it,")?;
        out::line("and confirmed that after the capability drop it cannot be removed.")?;
        out::line("")?;
        out::line("Network isolation holds.")
    } else {
        let err = String::from_utf8_lossy(&o.stderr);
        out::line("FAIL  the real namespace check did not pass:")?;
        for l in err.lines().filter(|l| !l.trim().is_empty()) {
            out::line(&format!("        {}", l.trim()))?;
        }
        Err("namespace check failed".into())
    }
}
