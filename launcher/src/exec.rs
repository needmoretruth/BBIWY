//! Starting a profile.
//!
//! Two halves. `run` executes outside; `inner` executes inside the namespace.
//! `pasta` is what joins them, and it re-enters this binary as `__inner`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::nft;
use crate::profile::{self, Profile, Strictness};

fn home() -> PathBuf {
    if let Ok(p) = std::env::var("BBIWY_HOME") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                .join(".local/share")
        });
    base.join("bbiwy")
}

/// Until BBIWY has its own build, the browser is supplied from outside.
fn browser() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BBIWY_BROWSER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("BBIWY_BROWSER points at nothing: {}", p.display()));
    }
    for cand in ["/opt/bbiwy/browser/bbiwy", "/usr/lib/bbiwy/bbiwy"] {
        if Path::new(cand).is_file() {
            return Ok(PathBuf::from(cand));
        }
    }
    Err("no browser found. Set BBIWY_BROWSER to its path.".into())
}

/// Outside. Build the namespace, then re-enter ourselves inside it.
pub fn run(name: &str) -> Result<(), String> {
    let p = profile::find(name)
        .ok_or_else(|| format!("unknown profile: {name}. Run `bbiwy list`."))?;
    if !p.ready {
        return Err(format!(
            "the {} route is not built yet. Available today: daily, hardened.",
            p.name
        ));
    }
    // Check before building anything, so a missing browser does not leave a
    // half-made namespace behind.
    browser()?;

    let me = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;

    // The most dangerous default in this whole program.
    //
    // pasta's --tcp-ports/--udp-ports default to `auto`, and `auto` is
    // fail-OPEN: it forwards ports nobody asked it to forward. Naming them
    // explicitly is what makes the allow-list mean anything.
    let forward = match p.relay_port() {
        Some(port) => port.to_string(),
        None => "none".to_string(),
    };

    let status = Command::new("pasta")
        .arg("--config-net")
        .args(["--tcp-ports", &forward])
        .args(["--udp-ports", "none"])
        .arg("--")
        .arg(&me)
        .arg("__inner")
        .arg(p.name)
        .status()
        .map_err(|e| format!("could not run pasta: {e}. Try `bbiwy doctor`."))?;

    if !status.success() {
        return Err("the browser did not exit cleanly inside the namespace.".into());
    }
    Ok(())
}

/// Inside. From here the outside network is no longer reachable.
pub fn inner(name: &str) -> Result<(), String> {
    let p = profile::find(name).ok_or_else(|| format!("unknown profile: {name}"))?;

    load_ruleset(p)?;

    let dir = home().join(p.name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create profile directory {}: {e}", dir.display()))?;

    // Before the browser starts, not after: the chrome reads these while it is
    // building the window, and a route marking that arrives late is a window
    // that was briefly unmarked.
    p.write_route_marking(&dir)?;

    let browser = browser()?;

    // Drop exactly the two capabilities that could undo the allow-list, and no
    // more.
    //
    // Dropping *everything* is the obvious move and it is wrong: it breaks
    // Firefox's own content sandbox, which writes `uid_map` when it creates its
    // per-process user namespace. Measured, all three in the same harness:
    //
    //   no drop              -> `nft flush ruleset` SUCCEEDS. Design defeated.
    //   --bounding-set=-all  -> allow-list safe, but every content process dies
    //                           with `Sandbox: writing /proc/self/uid_map: EPERM`
    //   -net_admin,-net_raw  -> allow-list safe AND the browser runs normally
    //
    // Removing them from the *bounding* set means they can never be regained,
    // by this process or anything it spawns.
    let mut cmd = Command::new("setpriv");
    cmd.args(["--bounding-set=-net_admin,-net_raw", "--no-new-privs", "--"])
        .arg(&browser)
        .args(["--profile", &dir.to_string_lossy()])
        .arg("--no-remote")
        // Informational only. Profile class is decided by the profile directory
        // path, not by this: a user can set an environment variable, and a lock
        // a user can lift is not a lock.
        .env("BBIWY_PROFILE", p.name)
        .env(
            "BBIWY_STRICTNESS",
            match p.strictness {
                Strictness::Daily => "daily",
                Strictness::Hardened => "hardened",
            },
        );

    // Hand over rather than linger; there is no reason for this process to stay.
    use std::os::unix::process::CommandExt;
    let e = cmd.exec();
    Err(format!("could not start the browser: {e}"))
}

fn load_ruleset(p: &Profile) -> Result<(), String> {
    let rules = nft::ruleset(p);
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run nft: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("could not write to nft")?
        .write_all(rules.as_bytes())
        .map_err(|e| format!("could not send rules: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("could not wait for nft: {e}"))?;
    if !out.status.success() {
        // Refuse rather than continue. A profile without its allow-list is not
        // a degraded profile, it is an unprotected one.
        return Err(format!(
            "could not install the allow-list, so nothing will be started.\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
