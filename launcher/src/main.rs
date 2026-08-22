//! BBIWY launcher.
//!
//! It does one thing: **build an isolated network namespace for a profile,
//! leave open only the route that profile is allowed to use, drop the
//! capabilities that could undo that, and start the browser.**
//!
//! Two decisions shape everything else.
//!
//! 1. **No privilege at runtime.** No setuid helper, no file capabilities, no
//!    polkit action, no system service. That is where tools in this category
//!    have historically been broken, so the attack surface is simply not
//!    created. Root is needed once, at install time, to place an AppArmor
//!    profile — the same thing Firefox, Chrome and Brave already do.
//! 2. **No syscalls of our own.** `pasta`, `nft` and `setpriv` already exist
//!    and are already audited. Composing them in a fixed order means this
//!    program contains no `unsafe`, has no dependencies, and can be understood
//!    by reading the commands it runs.
//!
//! Flow:
//!
//! ```text
//!   bbiwy run tor
//!     └ pasta --config-net --tcp-ports <route> --udp-ports none
//!         └ bbiwy __inner <profile>       ← inside. the outside is now invisible
//!             ├ nft -f -                  ← allow-list, with counters
//!             └ setpriv --bounding-set=-net_admin,-net_raw --no-new-privs
//!                 └ browser --profile <dir>
//! ```
#![forbid(unsafe_code)]

mod exec;
mod nft;
mod out;
mod preflight;
mod profile;

use std::process::ExitCode;

const USAGE: &str = "\
BBIWY — a browser where every network path is sealed in its own profile

Usage:
  bbiwy doctor            check whether isolation actually holds on this machine
  bbiwy list              show the profiles
  bbiwy run <profile>     start a profile inside its isolated namespace

Profiles: daily · hardened · tor · i2p · session

Environment:
  BBIWY_BROWSER   path to the browser binary (default: the install location)
  BBIWY_HOME      where profiles live (default: ~/.local/share/bbiwy)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    let r = match cmd {
        "doctor" => preflight::doctor(),
        "list" => profile::list(),
        "run" => match args.get(2) {
            Some(name) => exec::run(name),
            None => Err("a profile name is required. Run `bbiwy list` to see them.".into()),
        },
        // Where we re-enter ourselves, inside the namespace. Not meant to be
        // called by hand.
        "__inner" => match args.get(2) {
            Some(name) => exec::inner(name),
            None => Err("__inner needs a profile name".into()),
        },
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
