//! The pasta command line.
//!
//! pasta's defaults are built for convenience, and three of them are fail-open
//! for this purpose. Every forwarding option is therefore named explicitly —
//! measured on pasta 2024_02_20 (Ubuntu 24.04), 2024_09_06 and 2026_09_25:
//!
//! | option                          | default | what the default does here              |
//! |---------------------------------|---------|-----------------------------------------|
//! | `--tcp-ports` / `--udp-ports`   | `auto`  | binds **host** ports and forwards them  |
//! |                                 |         | *into* the namespace                    |
//! | `--tcp-ns` / `--udp-ns`         | `auto`  | every port bound on the host's loopback |
//! |                                 |         | appears on the namespace's loopback     |
//! | (gateway mapping)               | on      | the gateway address reaches the host's  |
//! |                                 |         | loopback                                |
//!
//! With `--tcp-ns` left at `auto`, a database, a development server, or the
//! local Tor SOCKS port on the host was reachable from inside the namespace —
//! and passed the allow-list's loopback rule without being counted. With
//! `--tcp-ports 9150`, pasta tried to bind the Tor port on the host itself, and
//! exited when tor already held it. Both were the launcher's own previous
//! command line.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use crate::profile::Relay;

/// The way back in.
///
/// Distributions that ship an AppArmor profile for pasta (Ubuntu 25.04 and
/// later, Debian 13) let it start commands from `/usr/bin` and `/bin` only. The
/// launcher usually lives in `~/.local/bin`, so it is started through `env`,
/// which is always in `/usr/bin`. Everywhere else this costs one exec.
const TRAMPOLINE: &str = "/usr/bin/env";

/// Builds the namespace for `relay` and runs `program args` inside it.
pub fn command(pasta: &Path, relay: Option<Relay>, program: &Path, args: &[&OsStr]) -> Command {
    let relay_port = match relay {
        Some(r) => r.port().to_string(),
        None => "none".to_string(),
    };

    let mut cmd = Command::new(pasta);
    cmd.arg("--quiet")
        // Give the namespace an interface and routes. A direct profile needs
        // them to go anywhere; a proxied one keeps them so that anything that
        // tries to leave reaches the allow-list and is counted, rather than
        // failing silently for want of a route.
        .arg("--config-net")
        // Nothing from the host into the namespace.
        .args(["--tcp-ports", "none", "--udp-ports", "none"])
        // From the namespace to the host's loopback: the relay, and nothing
        // else. No UDP at all.
        .args(["--tcp-ns", &relay_port, "--udp-ns", "none"])
        // The gateway address is the gateway, not a second door to the host.
        .arg("--no-map-gw")
        .arg("--");
    // pasta stays in the foreground while it runs a command, and exits with
    // that command's status.
    if Path::new(TRAMPOLINE).is_file() {
        cmd.arg(TRAMPOLINE);
    }
    cmd.arg(program).args(args);
    cmd
}
