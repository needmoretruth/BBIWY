//! Starting a profile.
//!
//! Two halves. `run` executes outside; `inner` executes inside the namespace.
//! `pasta` is what joins them: it builds the namespace and re-enters this
//! binary as `__inner`.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::browser::{self, Drift};
use crate::profile::{self, Profile, Relay};
use crate::{apparmor, install, nft, out, pasta, paths, prefs, status, sys};

/// Browser options that choose a different profile — which would put the
/// window on a profile this launcher did not seal. Compared without leading
/// dashes and case-insensitively, the way Gecko reads them.
const PROFILE_SWITCHES: &[&str] = &["p", "profile", "profilemanager", "createprofile", "migration"];

fn check_args(args: &[OsString]) -> Result<(), String> {
    for a in args {
        let s = a.to_string_lossy();
        let bare = s.trim_start_matches('-');
        if bare.len() == s.len() {
            // Not an option: a URL, or the value of the option before it.
            continue;
        }
        let key = bare.split('=').next().unwrap_or("").to_ascii_lowercase();
        if PROFILE_SWITCHES.contains(&key.as_str()) {
            return Err(format!(
                "`{s}` is not allowed: it would open a different profile than the one this launcher seals."
            ));
        }
    }
    Ok(())
}

/// Checks that the route's daemon is there before anything is built, so that
/// the failure is a sentence rather than a browser showing a proxy error.
fn relay_up(p: &Profile, r: Relay) -> Result<(), String> {
    let daemon = p.daemon.unwrap_or("its relay");
    match sys::tcp_listener(r.port()) {
        Some(l) if l.takes_v4() => Ok(()),
        Some(_) => Err(format!(
            "the {} route needs {daemon} on 127.0.0.1:{}, but it listens on the IPv6 loopback (::1) only.\n  Make it listen on 127.0.0.1.",
            p.name,
            r.port()
        )),
        None => {
            let mut msg = format!(
                "the {} route needs {daemon} accepting {} on 127.0.0.1:{}, and nothing is listening there.",
                p.name,
                match r {
                    Relay::Socks5(_) => "SOCKS5",
                    Relay::Http(_) => "HTTP proxy connections",
                },
                r.port()
            );
            if !p.hint.is_empty() {
                msg.push_str(&format!("\n  {}", p.hint));
            }
            for other in p.usual_ports.iter().filter(|o| **o != r.port()) {
                if sys::tcp_listener(*other).is_some_and(|l| l.takes_v4()) {
                    msg.push_str(&format!(
                        "\n  Something is listening on {other}. If that is {daemon}: `bbiwy install --{}-port {other}`.",
                        p.name
                    ));
                }
            }
            msg.push_str(&format!(
                "\n  If {daemon} listens on another port: `bbiwy install --{}-port <port>`.",
                p.name
            ));
            Err(msg)
        }
    }
}

/// Outside. Check everything that can be checked, build the namespace, and
/// re-enter this binary inside it.
pub fn run(name: &str, extra: &[OsString]) -> Result<(), String> {
    if sys::euid() == Some(0) {
        return Err("refusing to run as root. Start profiles as the user who browses; root is needed once, for `bbiwy apparmor`, and only on Ubuntu.".into());
    }
    let p = profile::find(name)
        .ok_or_else(|| format!("unknown profile: {name}. Run `bbiwy list`."))?;
    if !p.ready {
        return Err(format!(
            "the {} route is not built yet. Available today: {}.",
            p.name,
            profile::ready_names()
        ));
    }
    check_args(extra)?;

    // Before building anything, so that a missing or unlocked browser does not
    // leave a half-made namespace behind.
    let inst = browser::locate()?;
    let stamp = install::ensure_current(&inst)?;
    let relay = p.relay(&stamp.ports);
    if let Some(r) = relay {
        relay_up(p, r)?;
    }
    if let Some(r) = status::running(p.name) {
        return Err(format!(
            "the {} profile is already running (launcher pid {}). Use its window, or close it first.",
            p.name, r.launcher
        ));
    }
    apparmor::preflight()?;

    let pasta_bin = sys::tool("pasta").ok_or("pasta is not installed. Run `bbiwy doctor`.")?;
    let me = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;

    let mut inner_args: Vec<&OsStr> = vec![OsStr::new("__inner"), OsStr::new(p.name)];
    inner_args.extend(extra.iter().map(OsString::as_os_str));

    let mut child = pasta::command(&pasta_bin, relay, &me, &inner_args)
        .spawn()
        .map_err(|e| format!("could not run pasta: {e}. Try `bbiwy doctor`."))?;
    let record = status::record(p.name, std::process::id(), child.id());
    let st = child
        .wait()
        .map_err(|e| format!("could not wait for the profile: {e}"))?;
    drop(record);

    match st.code() {
        Some(0) => Ok(()),
        Some(c) => Err(format!("the {} profile stopped with status {c}.", p.name)),
        None => Err(format!("the {} profile was stopped by a signal.", p.name)),
    }
}

/// Inside. From here the outside network is no longer reachable.
pub fn inner(name: &str, extra: &[OsString]) -> Result<(), String> {
    let p = profile::find(name).ok_or_else(|| format!("unknown profile: {name}"))?;

    // The outer half checked the locks a moment ago. Check again rather than
    // trust it: this is the last point at which starting can be refused.
    let inst = browser::locate()?;
    let (stamp, drift) = inst.check()?;
    if drift.contains(&Drift::Locks) {
        return Err("the browser's lock files are not the ones this launcher writes, so nothing will be started. Run `bbiwy install`.".into());
    }
    let relay = p.relay(&stamp.ports);

    load_ruleset(relay)?;

    let home = paths::home()?;
    paths::private_dir(&home)?;
    let dir = home.join(p.name);
    paths::private_dir(&dir)?;

    // Before the browser starts, not after: the chrome reads these while it is
    // building the window, and a route marking that arrives late is a window
    // that was briefly unmarked.
    prefs::write_user_js(&dir, p)?;
    purge_stale_caches(&dir, &stamp.theme);

    let setpriv = sys::tool("setpriv").ok_or("setpriv (util-linux) is not installed")?;
    let me = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;

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
    //
    // setpriv does not become the browser directly: it becomes this binary
    // once more, as `__sealed`, which checks that the drop really happened and
    // only then becomes the browser. See `sealed`.
    let mut cmd = Command::new(setpriv);
    cmd.args(["--bounding-set=-net_admin,-net_raw", "--no-new-privs", "--"])
        .arg(me)
        .arg("__sealed")
        .arg(p.name)
        .args(extra);

    // Hand over rather than linger; there is no reason for this process to stay.
    use std::os::unix::process::CommandExt;
    let e = cmd.exec();
    Err(format!("could not start setpriv: {e}"))
}

/// Capability numbers, from linux/capability.h.
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;

/// What is wrong with this process's capabilities, if anything, for a process
/// about to become the browser: neither CAP_NET_ADMIN nor CAP_NET_RAW in any
/// set, and no_new_privs on.
fn unsealed_because() -> Option<String> {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => return Some(format!("/proc/self/status is unreadable ({e})")),
    };
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
            .map(str::to_string)
    };
    let net = (1u64 << CAP_NET_ADMIN) | (1u64 << CAP_NET_RAW);
    for (key, set) in [
        ("CapBnd:", "bounding"),
        ("CapPrm:", "permitted"),
        ("CapEff:", "effective"),
        ("CapInh:", "inheritable"),
        ("CapAmb:", "ambient"),
    ] {
        let Some(bits) = field(key).and_then(|v| u64::from_str_radix(&v, 16).ok()) else {
            return Some(format!("the {set} capability set cannot be read"));
        };
        if bits & net != 0 {
            return Some(format!(
                "CAP_NET_ADMIN or CAP_NET_RAW is still in the {set} set ({key} {bits:016x})"
            ));
        }
    }
    if field("NoNewPrivs:").as_deref() != Some("1") {
        return Some("no_new_privs is not set".into());
    }
    None
}

/// Inside, after the capability drop: check that it took, then become the
/// browser.
///
/// setpriv needs CAP_SETPCAP to drop from the bounding set, and when that is
/// missing it can carry on without the drop and without a word. Measured: in
/// an environment where no_new_privs was already set, pasta's child kept only
/// three capabilities, CAP_SETPCAP not among them; setpriv ran its command
/// with the bounding set untouched and CAP_NET_ADMIN still effective, and
/// `nft flush ruleset` succeeded — the allow-list could have been removed by
/// the browser. So the process that is about to exec the browser reads its own
/// capability sets, and anything but a clean drop refuses to start.
pub fn sealed(name: &str, extra: &[OsString]) -> Result<(), String> {
    if let Some(why) = unsealed_because() {
        return Err(format!(
            "the capability drop did not take effect — {why}. The browser could remove its own allow-list, so it will not be started.\n  This happens when the launcher runs where new privileges are already forbidden (no_new_privs, as some sandboxes and service managers set). Run `bbiwy doctor` from an ordinary desktop session."
        ));
    }
    let p = profile::find(name).ok_or_else(|| format!("unknown profile: {name}"))?;
    let inst = browser::locate()?;
    let dir = paths::profile_dir(p.name)?;

    let mut cmd = Command::new(&inst.binary);
    cmd.arg("--profile")
        .arg(&dir)
        .arg("--no-remote")
        // Its own window class, so that a dock or taskbar groups each route's
        // windows apart from the others' (and from the menu entry's name).
        .arg("--class")
        .arg(format!("bbiwy-{}", p.name))
        .args(extra)
        // Informational, except for one thing: the lock file reads it to take
        // the route marking *away* from a window the launcher did not start.
        // Which locks apply is decided by the profile directory, never by this.
        .env("BBIWY_PROFILE", p.name)
        .env("BBIWY_STRICTNESS", p.strictness_name());

    use std::os::unix::process::CommandExt;
    let e = cmd.exec();
    Err(format!("could not start the browser: {e}"))
}

/// Gecko keeps compiled chrome in the profile. When the theme changes under it,
/// that cache can outlive the change, so it is dropped once per theme.
fn purge_stale_caches(dir: &Path, theme: &str) {
    let mark = dir.join(".bbiwy-theme");
    if std::fs::read_to_string(&mark).ok().as_deref() == Some(theme) {
        return;
    }
    let _ = std::fs::remove_dir_all(dir.join("startupCache"));
    let _ = std::fs::write(&mark, theme);
}

fn load_ruleset(relay: Option<Relay>) -> Result<(), String> {
    let rules = nft::ruleset(relay);
    let nft = sys::tool("nft").ok_or("nft (nftables) is not installed")?;
    let mut child = Command::new(nft)
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

/// `bbiwy explain <profile>`: everything that profile gets, as the exact
/// commands and rules — so that what the launcher does can be checked by
/// reading it, not by trusting it.
pub fn explain(name: &str) -> Result<(), String> {
    if name == "--lock-file" {
        let ports = browser::locate()
            .ok()
            .and_then(|i| i.stamp().ok().flatten())
            .map(|s| s.ports)
            .unwrap_or_default();
        return out::text(&prefs::autoconfig(&ports));
    }
    let p = profile::find(name)
        .ok_or_else(|| format!("unknown profile: {name}. Run `bbiwy list`."))?;
    let inst = browser::locate().ok();
    let stamp = inst.as_ref().and_then(|i| i.stamp().ok().flatten());
    let ports = stamp.as_ref().map(|s| s.ports.clone()).unwrap_or_default();
    let relay = p.relay(&ports);

    out::line(&format!(
        "{} {} — {}, {}{}",
        p.glyph,
        p.name,
        p.route(&ports),
        p.strictness_name(),
        if p.ready { "" } else { " (not built yet)" }
    ))?;
    if stamp.is_none() {
        out::line("(not installed yet: ports are the defaults)")?;
    }

    let pasta_bin = sys::tool("pasta").unwrap_or_else(|| "pasta".into());
    let me = std::env::current_exe().unwrap_or_else(|_| "bbiwy".into());
    let cmd = pasta::command(&pasta_bin, relay, &me, &[OsStr::new("__inner"), OsStr::new(p.name)]);
    let argv: Vec<String> = std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    out::line("\nThe namespace (outside):")?;
    out::line(&format!("  {}", argv.join(" ")))?;

    out::line("\nThe allow-list (inside, `nft -f -`):")?;
    for l in nft::ruleset(relay).lines() {
        out::line(&format!("  {l}"))?;
    }

    let dir = paths::profile_dir(p.name)?;
    let binary = inst
        .as_ref()
        .map(|i| i.binary.display().to_string())
        .unwrap_or_else(|| "<browser>".into());
    out::line("\nThe capability drop and the browser (inside):")?;
    out::line(&format!(
        "  setpriv --bounding-set=-net_admin,-net_raw --no-new-privs -- {binary} --profile {} --no-remote --class bbiwy-{}",
        dir.display(),
        p.name
    ))?;

    out::line("\nPreferences (lock = nothing in the profile can change it; default = the user may):")?;
    for pref in prefs::for_profile(p, relay) {
        out::line(&format!(
            "  {} {} = {}",
            if pref.locked { "lock   " } else { "default" },
            pref.name,
            pref.value
        ))?;
    }
    out::line(&format!(
        "  lock    bbiwy.path.{} = true when started by the launcher, else false (the others: false)",
        p.name
    ))?;
    Ok(())
}

/// `doctor`'s end-to-end check, run inside a namespace built exactly the way
/// `run` builds one: the allow-list must load, and once the capabilities are
/// dropped it must not be removable.
pub fn probe() -> Result<(), String> {
    load_ruleset(None)?;
    let nft = sys::tool("nft").ok_or("nft (nftables) is not installed")?;
    let setpriv = sys::tool("setpriv").ok_or("setpriv (util-linux) is not installed")?;

    // Readable before the drop: it is really there.
    let listed = Command::new(&nft)
        .args(["list", "table", "inet", "bbiwy"])
        .output()
        .map_err(|e| format!("could not run nft: {e}"))?;
    if !listed.status.success() {
        return Err("the allow-list did not load".into());
    }

    // Not removable after it. Checked by trying, not by listing: after the
    // drop, listing is denied too, so a listing would report a false failure
    // (MEASUREMENTS §7).
    let flush = Command::new(&setpriv)
        .args(["--bounding-set=-net_admin,-net_raw", "--no-new-privs", "--"])
        .arg(&nft)
        .args(["flush", "ruleset"])
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("could not run setpriv: {e}"))?;
    if flush.success() {
        let why = match unsealed_because() {
            // Not after the drop, but a hint: without CAP_SETPCAP here, setpriv
            // cannot drop from the bounding set at all.
            _ if !has_cap(8) => "setpriv could not drop from the bounding set: this process lacks CAP_SETPCAP, as happens when no_new_privs was already set before the launcher ran".to_string(),
            Some(w) => w,
            None => "the reason is unknown".to_string(),
        };
        return Err(format!(
            "after the capability drop, the allow-list could still be removed ({why}). `bbiwy run` refuses to start a browser in this state."
        ));
    }
    out::line("probe: allow-list loaded, and not removable after the capability drop")
}

/// Whether this process has a capability in its effective set.
fn has_cap(cap: u32) -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|bits| bits & (1u64 << cap) != 0)
}
