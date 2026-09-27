//! Which profiles are running, and what their allow-lists have counted.
//!
//! The counters are the ones the allow-list keeps inside each namespace
//! (`nft.rs`). After the capability drop nothing inside can read them — that is
//! the point of the drop — so they are read from outside, by entering the
//! namespace as its owner.

use std::path::PathBuf;
use std::process::Command;

use crate::out::{self, pad};
use crate::profile::PROFILES;
use crate::{browser, nft, paths, sys};

pub struct Running {
    /// The `bbiwy run` process, which waits for the profile.
    pub launcher: u32,
    /// pasta. Its child is the first process inside the namespace.
    pub pasta: u32,
}

fn state_file(name: &str) -> Result<PathBuf, String> {
    Ok(paths::runtime_dir()?.join(format!("{name}.pid")))
}

/// The running instance of a profile, if there is one.
///
/// A record is believed only while the launcher it names is alive *and* is
/// still `bbiwy run <name>` — pids are reused.
pub fn running(name: &str) -> Option<Running> {
    let text = std::fs::read_to_string(state_file(name).ok()?).ok()?;
    let mut it = text.split_whitespace().map(|s| s.parse::<u32>());
    let (Some(Ok(launcher)), Some(Ok(pasta))) = (it.next(), it.next()) else {
        return None;
    };
    let args = sys::cmdline(launcher)?;
    let is_ours = args.get(1).map(String::as_str) == Some("run")
        && args.get(2).map(String::as_str) == Some(name);
    if !is_ours || !sys::alive(launcher) || !sys::alive(pasta) {
        return None;
    }
    Some(Running { launcher, pasta })
}

/// Removes the record when the profile stops, however `run` returns.
pub struct Record(PathBuf);

impl Drop for Record {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Notes that a profile is running. Best effort: without the record the
/// profile runs just the same; only `status` cannot see it.
pub fn record(name: &str, launcher: u32, pasta: u32) -> Option<Record> {
    let dir = paths::runtime_dir().ok()?;
    paths::private_dir(&dir).ok()?;
    let path = state_file(name).ok()?;
    std::fs::write(&path, format!("{launcher} {pasta}\n")).ok()?;
    Some(Record(path))
}

/// The allow-list's counters inside a running profile, as (name, packets).
pub fn counters(r: &Running) -> Result<Vec<(String, u64)>, String> {
    let target = *sys::children(r.pasta)
        .first()
        .ok_or("the namespace has no process in it")?;
    let nsenter = sys::tool("nsenter").ok_or("nsenter (util-linux) is not installed")?;
    let nft = sys::tool("nft").ok_or("nft is not installed")?;
    // --preserve-credentials: entering the user namespace is enough to hold
    // its capabilities. Switching to its root as well would call setgroups(),
    // which a namespace set up by an unprivileged user forbids ("setgroups
    // failed: Operation not permitted" — measured).
    let out = Command::new(nsenter)
        .arg("--target")
        .arg(target.to_string())
        .args(["--user", "--net", "--preserve-credentials", "--"])
        .arg(nft)
        .args(["list", "counters", "table", "inet", "bbiwy"])
        .output()
        .map_err(|e| format!("could not run nsenter: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.lines().next().unwrap_or("nsenter failed").trim().to_string());
    }
    Ok(parse_counters(&String::from_utf8_lossy(&out.stdout)))
}

/// Reads `nft list counters` output:
///
/// ```text
/// table inet bbiwy {
///     counter allowed {
///         packets 445 bytes 91342
///     }
/// ```
fn parse_counters(text: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("counter ") {
            current = rest.split_whitespace().next().map(str::to_string);
        } else if let (Some(name), Some(rest)) = (current.as_ref(), t.strip_prefix("packets ")) {
            if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
                out.push((name.clone(), n));
            }
            current = None;
        }
    }
    out
}

pub fn status() -> Result<(), String> {
    let ports = browser::locate()
        .ok()
        .and_then(|i| i.stamp().ok().flatten())
        .map(|s| s.ports)
        .unwrap_or_default();

    out::line(&format!(
        "  {} {} {} {} {}",
        pad("PROFILE", 10),
        pad("ROUTE", 23),
        pad("STATE", 9),
        pad("ALLOWED", 9),
        "BLOCKED"
    ))?;
    out::line(&format!("  {}", "─".repeat(64)))?;

    let mut any = false;
    let mut problems = Vec::new();
    for p in PROFILES {
        let head = format!("  {} {}", pad(p.name, 10), pad(&p.route(&ports), 23));
        let Some(r) = running(p.name) else {
            out::line(&format!("{head} {}", pad("—", 9)))?;
            continue;
        };
        any = true;
        match counters(&r) {
            Ok(c) => {
                let get = |n: &str| c.iter().find(|(k, _)| k == n).map_or(0, |(_, v)| *v);
                let blocked: u64 = nft::BLOCKED.iter().map(|(n, _)| get(n)).sum();
                let detail = if blocked == 0 {
                    "0".to_string()
                } else {
                    let parts: Vec<String> = nft::BLOCKED
                        .iter()
                        .filter(|(n, _)| get(n) > 0)
                        .map(|(n, label)| format!("{label} {}", get(n)))
                        .collect();
                    format!("{blocked}  ({})", parts.join(", "))
                };
                out::line(&format!(
                    "{head} {} {} {detail}",
                    pad("running", 9),
                    pad(&get("allowed").to_string(), 9)
                ))?;
            }
            Err(e) => {
                out::line(&format!("{head} {} {} ?", pad("running", 9), pad("?", 9)))?;
                problems.push(format!("{}: counters unreadable — {e}", p.name));
            }
        }
    }
    out::line("")?;
    for pr in &problems {
        out::line(pr)?;
    }
    if any {
        out::line("Packets since the profile started. BLOCKED is what the allow-list dropped:")?;
        out::line("anything but zero means something inside tried to leave by another way.")?;
    } else {
        out::line("No profile is running.")?;
    }
    Ok(())
}
