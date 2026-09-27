//! BBIWY launcher.
//!
//! It does one thing: **build an isolated network namespace for a profile,
//! leave open only the route that profile is allowed to use, drop the
//! capabilities that could undo that, and start the browser** — with its
//! preferences locked to the same route.
//!
//! Two decisions shape everything else.
//!
//! 1. **No privilege at runtime.** No setuid helper, no file capabilities, no
//!    polkit action, no system service. That is where tools in this category
//!    have historically been broken, so the attack surface is simply not
//!    created. Root is needed once, at install time and only on Ubuntu 23.10+,
//!    to place an AppArmor profile — the same thing Firefox, Chrome and Brave
//!    already do.
//! 2. **No syscalls of our own.** `pasta`, `nft` and `setpriv` already exist
//!    and are already audited. Composing them in a fixed order means this
//!    program contains no `unsafe`, has no dependencies, and can be understood
//!    by reading the commands it runs.
//!
//! Flow:
//!
//! ```text
//!   bbiwy run tor
//!     └ pasta --config-net -t none -u none -T <relay> -U none --no-map-gw
//!         └ env bbiwy __inner tor        ← inside. the outside is now invisible
//!             ├ nft -f -                  ← allow-list, with counters
//!             └ setpriv --bounding-set=-net_admin,-net_raw --no-new-privs
//!                 └ browser --profile <dir>   ← its prefs locked by bbiwy.cfg
//! ```
#![forbid(unsafe_code)]

mod apparmor;
mod browser;
mod exec;
mod install;
mod nft;
mod out;
mod pasta;
mod paths;
mod preflight;
mod prefs;
mod profile;
mod status;
mod sys;
mod theme;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use profile::Ports;

const USAGE: &str = "\
BBIWY — a browser where every network path is sealed in its own profile

Usage:
  bbiwy install [options]      put a verified browser in place and lock it down
  bbiwy doctor                 check that isolation actually holds on this machine
  bbiwy list                   show the profiles and their routes
  bbiwy run <profile> [args]   start a profile inside its sealed namespace
  bbiwy status                 show running profiles and what their allow-lists counted
  bbiwy explain <profile>      print the exact commands, rules and locks a profile gets
                               (--lock-file prints the whole generated lock file)
  sudo bbiwy apparmor          Ubuntu 23.10+ only: the one file that needs root
                               (--print shows it, --remove takes it away)
  bbiwy uninstall [--purge]    remove the browser and the menu entries
                               (--purge deletes the profiles too)
  bbiwy version

Profiles: daily · hardened · tor · i2p · session

Install options:
  --from <file.tar.xz>   install this Mullvad Browser tarball; its .asc must be next to it
  --browser <dir>        adopt a Mullvad Browser already extracted in <dir>
  --reinstall            download the latest release even if one is installed
  --tor-port <port>      where tor's SOCKS port is (default 9150; a system tor uses 9050)
  --i2p-port <port>      where the I2P router's HTTP proxy is (default 4444)
  --no-desktop           do not create menu entries

Run arguments go to the browser: URLs, or options such as --private-window.
Options that would open a different profile are refused.

Environment:
  BBIWY_HOME      where profiles and the browser live (default: ~/.local/share/bbiwy)
  BBIWY_BROWSER   start this browser binary instead of the installed one
";

fn strings(args: &[OsString]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|a| {
            a.to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("argument is not valid UTF-8: {}", a.to_string_lossy()))
        })
        .collect()
}

fn parse_install(args: &[OsString]) -> Result<install::Options, String> {
    let args = strings(args)?;
    let mut o = install::Options {
        from: None,
        browser: None,
        ports: Ports::default(),
        reinstall: false,
        desktop: true,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |what: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs {what}"))
        };
        match a.as_str() {
            "--from" => o.from = Some(PathBuf::from(value("a tarball")?)),
            "--browser" => o.browser = Some(PathBuf::from(value("a directory")?)),
            "--reinstall" => o.reinstall = true,
            "--no-desktop" => o.desktop = false,
            other => match other
                .strip_prefix("--")
                .and_then(|s| s.strip_suffix("-port"))
            {
                Some(name) => {
                    let v = value("a port number")?;
                    let port: u16 = v.parse().map_err(|_| format!("not a port number: {v}"))?;
                    o.ports.set(name, port)?;
                }
                None => return Err(format!("unknown install option: {other}\n\n{USAGE}")),
            },
        }
    }
    if o.from.is_some() && o.browser.is_some() {
        return Err("--from and --browser cannot be combined: one installs a tarball, the other adopts a directory.".into());
    }
    Ok(o)
}

/// Everything after the profile name goes to the browser. A leading `--` is
/// accepted and dropped, for symmetry with other launchers.
fn browser_args(rest: &[OsString]) -> &[OsString] {
    match rest.first() {
        Some(a) if a == "--" => &rest[1..],
        _ => rest,
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let cmd = args.get(1).and_then(|a| a.to_str()).unwrap_or("");
    let rest: &[OsString] = if args.len() > 2 { &args[2..] } else { &[] };

    let r = match cmd {
        "install" => parse_install(rest).and_then(|o| install::install(&o)),
        "uninstall" => match strings(rest) {
            Ok(a) if a.is_empty() => install::uninstall(false),
            Ok(a) if a.len() == 1 && a[0] == "--purge" => install::uninstall(true),
            Ok(a) => Err(format!("unknown uninstall option: {}", a.join(" "))),
            Err(e) => Err(e),
        },
        "doctor" => preflight::doctor(),
        "list" => profile::list(),
        "status" => status::status(),
        "run" => match rest.first().and_then(|a| a.to_str()) {
            Some(name) => exec::run(name, browser_args(&rest[1..])),
            None => Err("a profile name is required. Run `bbiwy list` to see them.".into()),
        },
        "explain" => match rest.first().and_then(|a| a.to_str()) {
            Some(name) => exec::explain(name),
            None => Err("explain needs a profile name, or --lock-file.".into()),
        },
        "apparmor" => strings(rest).and_then(|a| apparmor::command(&a)),
        "version" | "--version" | "-V" => out::line(&format!(
            "bbiwy {} (lock schema {})",
            env!("CARGO_PKG_VERSION"),
            prefs::SCHEMA
        )),
        // Where we re-enter ourselves, inside the namespace. Not meant to be
        // called by hand.
        "__inner" => match rest.first().and_then(|a| a.to_str()) {
            Some(name) => exec::inner(name, &rest[1..]),
            None => Err("__inner needs a profile name".into()),
        },
        // After the capability drop: check it, then become the browser.
        "__sealed" => match rest.first().and_then(|a| a.to_str()) {
            Some(name) => exec::sealed(name, &rest[1..]),
            None => Err("__sealed needs a profile name".into()),
        },
        "__probe" => exec::probe(),
        "-h" | "--help" | "help" | "" => {
            return match out::text(USAGE) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        other => Err(format!("unknown command: {other}\n\n{USAGE}")),
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
