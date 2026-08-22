//! `bbiwy doctor` — does isolation actually hold on this machine?
//!
//! This exists because the failure mode that matters is not a crash. It is a
//! browser that starts normally on a machine where isolation silently does not
//! work, leaving someone believing they are protected when they are not.

use crate::out;
use crate::profile::pad;
use std::path::Path;
use std::process::Command;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// Whether isolation is impossible without this.
    pub fatal: bool,
}

fn which(bin: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .map(|d| Path::new(d).join(bin))
        .find(|p| p.is_file())
        .map(|p| p.display().to_string())
}

fn sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

pub fn checks() -> Vec<Check> {
    let mut out = Vec::new();

    for (bin, name, why) in [
        ("pasta", "pasta (passt)", "attaches the namespace to the network"),
        ("nft", "nftables", "installs the allow-list"),
        ("setpriv", "setpriv (util-linux)", "drops capabilities before the browser starts"),
    ] {
        let found = which(bin);
        out.push(Check {
            name,
            ok: found.is_some(),
            detail: match &found {
                Some(p) => format!("{p} — {why}"),
                None => format!("not found. Needed to {why}"),
            },
            fatal: true,
        });
    }

    // Unprivileged user namespaces. Restricted by default on Ubuntu 24.04+;
    // the AppArmor profile placed at install time is what lifts it.
    let restricted = sysctl("kernel.apparmor_restrict_unprivileged_userns").as_deref() == Some("1");
    let profile_installed = Path::new("/etc/apparmor.d/bbiwy").exists();
    out.push(Check {
        name: "unprivileged netns",
        ok: !restricted || profile_installed,
        detail: if !restricted {
            "unrestricted".into()
        } else if profile_installed {
            "AppArmor restricts this, but the BBIWY profile is installed".into()
        } else {
            "AppArmor is blocking it and the BBIWY profile is missing. \
             Re-run the installer (/etc/apparmor.d/bbiwy)"
                .into()
        },
        fatal: true,
    });

    // The namespace cannot touch the display layer. Under X11 any client can
    // read any other client's input and screen, so profiles are not isolated
    // from each other even though their traffic is.
    let (grade, detail) = display_grade();
    out.push(Check {
        name: "profile-to-profile",
        ok: grade != Grade::None,
        detail,
        fatal: false,
    });

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
        let mark = if c.ok {
            "OK  "
        } else if c.fatal {
            "FAIL"
        } else {
            "WARN"
        };
        out::line(&format!("  {mark}  {} {}", pad(c.name, 20), c.detail))?;
        if !c.ok && c.fatal {
            fatal_failed = true;
        }
    }
    out::line("")?;
    if fatal_failed {
        out::line("Isolation cannot be established. Fix the FAIL lines above first.")?;
        return Err("preflight failed".into());
    }
    out::line("Network isolation holds.")?;

    // Having the binaries is not the same as being able to use them.
    match Command::new("pasta")
        .args(["--config-net", "--tcp-ports", "none", "--udp-ports", "none", "--", "/bin/true"])
        .output()
    {
        Ok(o) if o.status.success() => out::line("Built a namespace for real, and it worked."),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let line = err.lines().find(|l| !l.contains("IPv6")).unwrap_or("").trim();
            out::line(&format!("WARN  could not actually create a namespace: {line}"))?;
            Err("namespace creation failed".into())
        }
        Err(e) => Err(format!("could not run pasta: {e}")),
    }
}
