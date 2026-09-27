//! Small facts about the machine, read from `/proc` and `PATH`.
//!
//! No dependencies and no `unsafe`, so nothing here calls into libc. What the
//! standard library does not expose is read from procfs instead.

use std::path::{Path, PathBuf};

/// Searched after `PATH`. Debian leaves the sbin directories out of an ordinary
/// user's `PATH`, and that is exactly where `nft` lives.
const SBIN: &[&str] = &["/usr/local/sbin", "/usr/sbin", "/sbin"];

/// Finds an executable by name.
///
/// Relative `PATH` entries are skipped: a `.` in `PATH` would let whatever sits
/// in the current directory stand in for `pasta` or `nft`.
pub fn tool(bin: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let from_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    from_path
        .into_iter()
        .filter(|d| d.is_absolute())
        .chain(SBIN.iter().map(PathBuf::from))
        .map(|d| d.join(bin))
        .find(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// A kernel tunable, e.g. `kernel.apparmor_restrict_unprivileged_userns`.
pub fn sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// The effective uid. The standard library has no getter for it without libc.
pub fn euid() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid: real effective saved filesystem
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Whether a file can be created in `dir` — asked by trying, because mode bits
/// say nothing about read-only mounts or ACLs.
pub fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".bbiwy-write-test-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// What is listening for TCP on the host at a port, as far as loopback clients
/// are concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Listener {
    Loopback4,
    Any4,
    Loopback6,
    Any6,
}

impl Listener {
    /// Whether a connection to 127.0.0.1 reaches it — the one address every
    /// proxied profile is locked to.
    pub fn takes_v4(self) -> bool {
        !matches!(self, Listener::Loopback6)
    }
}

/// Reads the host's listening sockets for `port` from procfs.
pub fn tcp_listener(port: u16) -> Option<Listener> {
    let mut found = None;
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // 0A is TCP_LISTEN.
            if f.len() < 4 || f[3] != "0A" {
                continue;
            }
            let Some((addr, p)) = f[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(p, 16).ok() != Some(port) {
                continue;
            }
            // Addresses are hex in host byte order: 127.0.0.1 is 0100007F.
            let kind = match (v6, addr) {
                (false, "00000000") => Some(Listener::Any4),
                (false, a) if a.len() == 8 && a.ends_with("7F") => Some(Listener::Loopback4),
                (true, "00000000000000000000000000000000") => Some(Listener::Any6),
                (true, "00000000000000000000000001000000") => Some(Listener::Loopback6),
                _ => None,
            };
            if let Some(k) = kind {
                if k.takes_v4() {
                    return Some(k);
                }
                found = Some(k);
            }
        }
    }
    found
}

/// State and parent of a process, from `/proc/<pid>/stat`.
fn stat(pid: u32) -> Option<(char, u32)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name sits in parentheses and may itself contain spaces or
    // parentheses, so the fields are counted from the last ')'.
    let rest = &s[s.rfind(')')? + 1..];
    let mut f = rest.split_whitespace();
    let state = f.next()?.chars().next()?;
    let ppid = f.next()?.parse().ok()?;
    Some((state, ppid))
}

pub fn alive(pid: u32) -> bool {
    matches!(stat(pid), Some((s, _)) if s != 'Z' && s != 'X')
}

/// The argument vector of a live process.
pub fn cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(
        raw.split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
    )
}

/// Live children of `pid`, lowest pid first.
pub fn children(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(child) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if matches!(stat(child), Some((s, ppid)) if ppid == pid && s != 'Z' && s != 'X') {
                out.push(child);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Pulls a string field out of a small, flat JSON object.
///
/// Enough for the two files this launcher reads — the release index and the
/// browser's `version.json` — without a JSON dependency. Not a JSON parser.
pub fn json_str(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(i) = text[from..].find(&needle) {
        let after = from + i + needle.len();
        from = after;
        let rest = text[after..].trim_start();
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(body) = rest.strip_prefix('"') else {
            continue;
        };
        let mut out = String::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => match chars.next()? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    other => out.push(other),
                },
                c => out.push(c),
            }
        }
        return None;
    }
    None
}
