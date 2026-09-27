//! `sudo bbiwy apparmor` — the one file that needs root, on Ubuntu 23.10 and
//! later.
//!
//! Ubuntu restricts unprivileged user namespaces by default
//! (`kernel.apparmor_restrict_unprivileged_userns = 1`). An unconfined program
//! that creates one is moved into the `unprivileged_userns` profile, which
//! denies it every capability there — so pasta gets a namespace it cannot set
//! up, and fails. A profile attached to pasta whose one rule is `userns,` lifts
//! the restriction for pasta and for nothing else. Measured on 24.04: with it
//! the namespace is entered; removed again, pasta fails (MEASUREMENTS §5).
//!
//! Three facts decide what the profile attaches to, and whether to place it at
//! all:
//!
//! - AppArmor attaches by the path that was executed, symlinks resolved. Every
//!   Debian and Ubuntu package makes `/usr/bin/pasta` a *hard link* to
//!   `/usr/bin/passt`, and a hard link has nothing to resolve to: the passt
//!   profile those packages ship (`/usr/bin/passt{,.avx2}`) never applies to
//!   pasta.
//! - On a CPU with AVX2, pasta re-executes itself as `<its own path>.avx2`, so
//!   that name is covered as well.
//! - Ubuntu 25.04 and later, and Debian 13, ship a pasta profile of their own.
//!   When two profiles attach to the same path equally well, the kernel uses
//!   neither ("conflicting profile attachments") and pasta runs unconfined —
//!   which, under the restriction, means it fails. A second profile would take
//!   the distribution's away rather than add to it, so none is placed there.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::out::{line, note, text};
use crate::sys::{euid, sysctl, tool};

/// Whether something lets pasta create its user namespace.
pub enum Coverage {
    /// Unprivileged user namespaces are not restricted here.
    NotNeeded,
    /// Restricted, and BBIWY's profile is in place.
    Ours,
    /// Restricted, and the distribution's own pasta profile allows it.
    Distro(String),
    /// Restricted, and nothing lets pasta through.
    Missing,
}

/// The profile's name, and the name of its file in [`DIR`]. The name is also
/// how the loaded policy is recognised as this one.
const NAME: &str = "bbiwy";
/// Where policy lives. The loader reads every file directly in it at boot.
const DIR: &str = "/etc/apparmor.d";
/// `DIR/disable/<file>` exists for every file `aa-disable` has switched off;
/// the loader skips those.
const DISABLED: &str = "disable";
const ENABLED: &str = "/sys/module/apparmor/parameters/enabled";
const RESTRICT: &str = "kernel.apparmor_restrict_unprivileged_userns";
/// Every loaded profile, one `name (mode)` per line. Only root may read it.
const LOADED: &str = "/sys/kernel/security/apparmor/profiles";
/// One directory per loaded profile, named `<name>.<n>`, each holding a `name`
/// file that anyone may read.
const LOADED_DIRS: &str = "/sys/kernel/security/apparmor/policy/profiles";

const USAGE: &str = "\
Usage:
  sudo bbiwy apparmor           place the profile that lets pasta through, and load it
  sudo bbiwy apparmor --force   place it even where user namespaces are not restricted
  bbiwy apparmor --print        show the profile without placing it
  sudo bbiwy apparmor --remove  unload the profile and delete it
";

/// Whether AppArmor is holding unprivileged user namespaces back here.
pub fn restricted() -> bool {
    enabled() && sysctl(RESTRICT).as_deref() == Some("1")
}

fn enabled() -> bool {
    fs::read_to_string(ENABLED).is_ok_and(|s| s.trim() == "Y")
}

/// pasta as the kernel names it when `run` executes it: the binary found on
/// `PATH`, with every symlink resolved.
fn pasta() -> Option<PathBuf> {
    fs::canonicalize(tool("pasta")?).ok()
}

fn our_file() -> PathBuf {
    Path::new(DIR).join(NAME)
}

/// What stands between pasta and its namespace, in more detail than
/// [`Coverage`] — enough for a message to say what to do about it.
enum State {
    NotNeeded,
    /// Restricted, and pasta is not installed: there is nothing to attach a
    /// profile to yet.
    NoPasta,
    Ours,
    /// BBIWY's profile is on disk, but the kernel does not have it.
    NotLoaded,
    /// BBIWY's profile and the distribution's (this file) both attach to pasta.
    Conflict(String),
    Distro(String),
    Missing(PathBuf),
}

fn state() -> State {
    if !restricted() {
        return State::NotNeeded;
    }
    let Some(pasta) = pasta() else {
        return State::NoPasta;
    };
    let Some(path) = pasta.to_str() else {
        // No attachment written as text can name this path.
        return State::Missing(pasta);
    };
    let ours = fs::read_to_string(our_file())
        .is_ok_and(|t| declared(&t).iter().any(|(_, a)| a.as_deref().is_some_and(|a| matches(a, path))));
    match (ours, distro(Path::new(DIR), path)) {
        // The loader reads both at every boot, whatever is loaded right now.
        (true, Some(other)) => State::Conflict(other),
        (true, None) if loaded() == Some(false) => State::NotLoaded,
        (true, None) => State::Ours,
        (false, Some(other)) => State::Distro(other),
        (false, None) => State::Missing(pasta),
    }
}

pub fn coverage() -> Coverage {
    match state() {
        State::NotNeeded => Coverage::NotNeeded,
        State::Ours => Coverage::Ours,
        State::Distro(other) => Coverage::Distro(other),
        State::NoPasta | State::NotLoaded | State::Conflict(_) | State::Missing(_) => Coverage::Missing,
    }
}

/// Refuses to build a namespace pasta will not be allowed to set up, so that
/// the failure is a sentence and a command rather than pasta's own error.
pub fn preflight() -> Result<(), String> {
    let why = match state() {
        State::NotNeeded | State::Ours | State::Distro(_) => return Ok(()),
        // Without pasta there is nothing a profile could attach to. The caller
        // reports the missing binary next, and that is the thing to fix first.
        State::NoPasta => return Ok(()),
        State::NotLoaded => format!(
            "BBIWY's AppArmor profile is in {}, but it is not loaded, so pasta cannot create the namespace each profile is sealed in.\n  Loading it needs root:",
            our_file().display()
        ),
        State::Conflict(other) => format!(
            "BBIWY's AppArmor profile and the distribution's ({DIR}/{other}) both attach to pasta, and when two do, the kernel uses neither — so pasta cannot create the namespace each profile is sealed in.\n  The distribution's is the one to keep. Taking BBIWY's out needs root:"
        ),
        State::Missing(pasta) => format!(
            "this system restricts unprivileged user namespaces, and nothing lets pasta ({}) create the one each profile is sealed in.\n  Ubuntu has done this by default since 23.10. An AppArmor profile attached to pasta lifts it for pasta alone — the same kind of profile Ubuntu ships for Firefox, Chrome and Brave.\n  Placing it needs root, once:",
            pasta.display()
        ),
    };
    Err(format!("{why}\n    sudo {} apparmor", me()))
}

/// `bbiwy apparmor [--print | --remove | --force]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => install(false),
        ["--force"] => install(true),
        ["--print"] => {
            let pasta = pasta().ok_or("pasta is not installed, so there is nothing for the profile to attach to.")?;
            text(&render(&pasta)?)
        }
        ["--remove"] => remove(),
        ["-h" | "--help"] => text(USAGE),
        [_, _, ..] => Err(format!("apparmor takes one option at a time, not `{}`.\n\n{USAGE}", args.join(" "))),
        _ => Err(format!("unknown apparmor option: {}\n\n{USAGE}", args.join(" "))),
    }
}

/// The profile, attached to the pasta at `pasta` — the same shape as the
/// profiles Ubuntu ships for Chrome and Brave.
fn render(pasta: &Path) -> Result<String, String> {
    let attach = attachment(pasta)?;
    Ok(format!(
        "# BBIWY — lets pasta create the user namespace each profile is sealed in.
#
# Ubuntu 23.10 and later restrict unprivileged user namespaces: a program
# needs an AppArmor profile that allows them before it can set one up. This
# profile attaches to pasta and to nothing else. It is marked unconfined, so
# it takes nothing away, and its single rule, `userns`, is all it adds.
# Ubuntu ships the same kind of profile for Firefox, Chrome and Brave.
#
# Written by `bbiwy apparmor`. Remove it with `sudo bbiwy apparmor --remove`.

abi <abi/4.0>,
include <tunables/global>

profile {NAME} {attach} flags=(unconfined) {{
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/{NAME}>
}}
"
    ))
}

/// What the profile attaches to: pasta's own path and, where there is one, the
/// AVX2 build next to it.
fn attachment(pasta: &Path) -> Result<String, String> {
    let p = pasta
        .to_str()
        .ok_or_else(|| format!("pasta's path is not valid UTF-8, so no profile can name it: {}", pasta.display()))?;
    // An attachment is a pattern, not a literal: `*`, `?`, `[`, `{`, `@{` and
    // escapes all mean something in it, and a quote or a line break would end
    // it early. A path holding anything like that is refused rather than
    // escaped, so that the profile attaches to exactly what it reads as.
    if let Some(c) = p
        .chars()
        .find(|c| !(c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '~' | ' ')))
    {
        return Err(format!(
            "pasta is at {p}, and `{}` would mean something else in an AppArmor profile.\n  Use a pasta with a plainer path; the distribution's passt package puts it in /usr/bin.",
            c.escape_default()
        ));
    }
    let mut a = p.to_string();
    if Path::new(&format!("{p}.avx2")).is_file() {
        a.push_str("{,.avx2}");
    }
    if a.contains(' ') {
        a = format!("\"{a}\"");
    }
    Ok(a)
}

/// Whether an attachment names `path`.
///
/// Only the forms distributions use for a binary like this one are understood:
/// literal text and `{a,b}` alternation, nested or not — `/usr/bin/pasta`,
/// `/usr/bin/pasta{,.avx2}`, `/usr/{bin,sbin}/runc`. A pattern with anything
/// else in it (`*`, `?`, `[…]`, `@{variable}`, an escape) is treated as not
/// naming it: what cannot be evaluated here cannot be claimed to cover pasta.
fn matches(pattern: &str, path: &str) -> bool {
    expand(pattern).is_some_and(|all| all.iter().any(|p| p == path))
}

/// Every path a pattern stands for, or `None` for syntax beyond literals and
/// alternation — or for more alternatives than any real attachment has.
fn expand(pattern: &str) -> Option<Vec<String>> {
    const MOST: usize = 1024;
    let plain = |s: &str| !s.contains(['*', '?', '[', ']', '{', '}', '\\', '^']) && !s.contains("@{");

    let Some(open) = pattern.find('{') else {
        return plain(pattern).then(|| vec![pattern.to_string()]);
    };
    let (head, rest) = (&pattern[..open], &pattern[open + 1..]);
    if !plain(head) {
        return None;
    }
    // The alternatives run to the matching brace, split at the commas that are
    // not inside a nested group.
    let (mut alts, mut depth, mut start, mut close) = (Vec::new(), 0usize, 0, None);
    for (i, c) in rest.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => {
                alts.push(&rest[start..i]);
                close = Some(i);
                break;
            }
            '}' => depth -= 1,
            ',' if depth == 0 => {
                alts.push(&rest[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let tails = expand(&rest[close? + 1..])?;
    let mut out = Vec::new();
    for alt in alts {
        for a in expand(alt)? {
            for t in &tails {
                out.push(format!("{head}{a}{t}"));
                if out.len() > MOST {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// The profiles a policy file declares at its top level, as `(name,
/// attachment)`. Nested profiles and hats are left out: they apply only when
/// their parent hands over to them, never to a program started from outside.
fn declared(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    for raw in text.lines() {
        // Comments may hold braces of their own.
        let l = raw.split('#').next().unwrap_or("");
        if depth == 0 {
            out.extend(header(l));
        }
        for c in l.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    out
}

/// `(name, attachment)` if the line opens a profile.
fn header(l: &str) -> Option<(String, Option<String>)> {
    let w = words(l);
    let first = w.first()?;
    if first == "profile" {
        let name = w.get(1)?.clone();
        let attach = w
            .get(2)
            .filter(|a| a.starts_with('/') || a.starts_with("@{"))
            .cloned()
            // A profile named by a path, with no attachment of its own,
            // attaches by its name.
            .or_else(|| name.starts_with('/').then(|| name.clone()));
        return Some((name, attach));
    }
    // The older form, without the keyword: the name is the attachment. What
    // follows it tells it apart from a file rule, which ends in permissions.
    let opens = w.get(1).is_some_and(|n| n == "{" || n.starts_with("flags=") || n.starts_with('('));
    (first.starts_with('/') && opens).then(|| (first.clone(), Some(first.clone())))
}

/// Splits a line at whitespace, keeping double-quoted words whole — the way a
/// name like `"MongoDB Compass"` is written.
fn words(l: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in l.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// The first policy file other than BBIWY's that the loader will load and that
/// attaches a profile to `pasta`.
fn distro(dir: &Path, pasta: &str) -> Option<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names.into_iter().find(|n| {
        n != NAME
            && !skipped(n)
            && dir.join(DISABLED).join(n).symlink_metadata().is_err()
            && fs::metadata(dir.join(n)).is_ok_and(|m| m.is_file())
            && fs::read_to_string(dir.join(n)).is_ok_and(|t| {
                declared(&t)
                    .iter()
                    .any(|(name, a)| name != NAME && a.as_deref().is_some_and(|a| matches(a, pasta)))
            })
    })
}

/// Files the loader passes over when it reads the directory: dot files, the
/// README, and what package managers and editors leave behind. A profile in
/// one of them is never loaded, so it attaches to nothing.
fn skipped(name: &str) -> bool {
    const LEFTOVERS: &[&str] = &[
        ".dpkg-new", ".dpkg-old", ".dpkg-dist", ".dpkg-bak", ".dpkg-remove", ".pacsave", ".pacnew",
        ".rpmnew", ".rpmsave", ".orig", ".rej", "~",
    ];
    name.starts_with('.') || name == "README" || LEFTOVERS.iter().any(|s| name.ends_with(s))
}

/// Whether the kernel has a profile named `bbiwy`, when that can be told.
fn loaded() -> Option<bool> {
    if let Ok(list) = fs::read_to_string(LOADED) {
        let prefix = format!("{NAME} ");
        return Some(list.lines().any(|l| l.starts_with(&prefix)));
    }
    // Everyone else asks profile by profile. Only a complete reading is an
    // answer: a "no" from a partial one would report a working profile as
    // missing.
    let prefix = format!("{NAME}.");
    for e in fs::read_dir(LOADED_DIRS).ok()? {
        let e = e.ok()?;
        if !e.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)) {
            continue;
        }
        if fs::read_to_string(e.path().join("name")).ok()?.trim_end() == NAME {
            return Some(true);
        }
    }
    Some(false)
}

/// How to type this binary after `sudo`. sudo resets `PATH` to the system
/// directories, and the launcher usually lives in `~/.local/bin`, so a bare
/// `bbiwy` would not be found.
fn me() -> String {
    let p = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "bbiwy".into());
    if p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+')) {
        p
    } else {
        format!("'{}'", p.replace('\'', r"'\''"))
    }
}

fn need_root(what: &str, args: &str) -> Result<(), String> {
    if euid() == Some(0) {
        return Ok(());
    }
    Err(format!("{what} needs root. Run it with sudo:\n    sudo {} {args}", me()))
}

/// Why no profile is needed, for a system that does not restrict namespaces.
fn unrestricted_because() -> String {
    if !enabled() {
        "AppArmor is not enabled".into()
    } else {
        match sysctl(RESTRICT) {
            None => "this kernel has no such restriction".into(),
            Some(v) => format!("{RESTRICT} is {v}"),
        }
    }
}

fn install(force: bool) -> Result<(), String> {
    need_root(
        &format!("placing the profile in {DIR}"),
        if force { "apparmor --force" } else { "apparmor" },
    )?;
    let file = our_file();
    if !restricted() && !force {
        line(&format!(
            "Nothing to do: this system does not restrict unprivileged user namespaces ({}), so pasta needs no profile.",
            unrestricted_because()
        ))?;
        if file.exists() {
            line(&format!(
                "BBIWY's profile from before is still in {}. It does no harm here; `--remove` takes it away.",
                file.display()
            ))?;
        }
        return line("`--force` places the profile anyway, for a system that will restrict them later.");
    }

    let pasta = pasta().ok_or("pasta is not installed, so there is nothing for the profile to attach to. Install the passt package, then run this again.")?;
    if let Some(other) = pasta.to_str().and_then(|p| distro(Path::new(DIR), p)) {
        if file.exists() {
            let unloaded = unload(&file)?;
            fs::remove_file(&file).map_err(|e| format!("could not delete {}: {e}", file.display()))?;
            line(&format!(
                "The distribution now ships its own profile for pasta ({DIR}/{other}). BBIWY's attached to the same binary, and with two the kernel uses neither, so BBIWY's has been {}.",
                if unloaded { "unloaded and deleted" } else { "deleted" }
            ))?;
            return line("pasta can create its namespace through the distribution's profile.");
        }
        line(&format!(
            "Nothing to do: the distribution's own profile for pasta ({DIR}/{other}) already lets it create its namespace."
        ))?;
        return line("A second profile attached to the same binary would make the kernel use neither, so none is placed.");
    }

    let profile = render(&pasta)?;
    root_only(&pasta)?;
    let mut avx2 = pasta.clone().into_os_string();
    avx2.push(".avx2");
    let avx2 = PathBuf::from(avx2);
    if avx2.is_file() {
        root_only(&avx2)?;
    }
    // Before anything is written: without the parser the file could not be
    // loaded, and an unloaded file is only something to clean up later.
    let parser = tool("apparmor_parser")
        .ok_or("apparmor_parser is not installed, so the profile could not be loaded. It comes with the apparmor package.")?;

    let before = fs::read(&file).ok();
    let changed = before.as_deref() != Some(profile.as_bytes());
    if changed {
        write_atomic(&file, profile.as_bytes())?;
    }
    note("Loading it with apparmor_parser…");
    let o = Command::new(&parser)
        .args(["-r", "-W"])
        .arg(&file)
        .output()
        .map_err(|e| format!("could not run {}: {e}", parser.display()))?;
    let err = String::from_utf8_lossy(&o.stderr);
    if !o.status.success() {
        // A file that does not load would fail again at every boot, and take
        // the loader's status with it. Put back what was there.
        let undone = if !changed {
            "nothing was changed".to_string()
        } else {
            let put_back = match &before {
                Some(b) => write_atomic(&file, b),
                None => fs::remove_file(&file).map_err(|e| format!("could not delete {}: {e}", file.display())),
            };
            match put_back {
                Ok(()) if before.is_some() => "the previous file was put back".to_string(),
                Ok(()) => "it was taken back out".to_string(),
                Err(e) => format!("it could not be taken back out either ({e})"),
            }
        };
        return Err(format!(
            "apparmor_parser could not load the profile, and {undone}:\n{}",
            indent(&err)
        ));
    }
    for l in err.lines().filter(|l| !l.trim().is_empty()) {
        note(&format!("  apparmor_parser: {}", l.trim()));
    }
    if loaded() == Some(false) {
        return Err(format!(
            "apparmor_parser reported success, but the kernel has no profile named {NAME}. Check `sudo aa-status`."
        ));
    }

    line(&if changed {
        format!("Placed {} and loaded it.", file.display())
    } else {
        format!("{} was already in place; loaded it again.", file.display())
    })?;
    line(&format!(
        "pasta ({}) can now create the user namespace each profile is sealed in.",
        pasta.display()
    ))?;
    line("It is loaded again at every boot. `bbiwy doctor`, run as the user who browses, checks it end to end.")?;
    line(&format!("To take it away: sudo {} apparmor --remove", me()))
}

fn remove() -> Result<(), String> {
    need_root(&format!("removing the profile from {DIR}"), "apparmor --remove")?;
    let file = our_file();
    if file.symlink_metadata().is_err() {
        return line(&format!("There is nothing to remove: {} does not exist.", file.display()));
    }
    let unloaded = unload(&file)?;
    fs::remove_file(&file).map_err(|e| format!("could not delete {}: {e}", file.display()))?;
    line(&format!(
        "{} {}.",
        if unloaded { "Unloaded and deleted" } else { "Deleted" },
        file.display()
    ))?;
    if matches!(state(), State::Missing(_)) {
        line("pasta can no longer create its namespace here, so profiles will not start until something lets it through again.")?;
    }
    Ok(())
}

/// Takes BBIWY's profile out of the kernel, and says whether there was one to
/// take out. Not being loaded is the state asked for, so it is not an error.
fn unload(file: &Path) -> Result<bool, String> {
    if !enabled() || loaded() == Some(false) {
        return Ok(false);
    }
    let parser = tool("apparmor_parser").ok_or(
        "apparmor_parser is not installed, so the loaded profile cannot be taken out of the kernel. It comes with the apparmor package.",
    )?;
    let o = Command::new(&parser)
        .arg("-R")
        .arg(file)
        .output()
        .map_err(|e| format!("could not run {}: {e}", parser.display()))?;
    let err = String::from_utf8_lossy(&o.stderr);
    if o.status.success() {
        return Ok(true);
    }
    if err.contains("Profile doesn't exist") {
        return Ok(false);
    }
    Err(format!(
        "apparmor_parser could not unload {}, so it was left in place:\n{}",
        file.display(),
        indent(&err)
    ))
}

/// The profile lets whatever sits at its path create user namespaces. If anyone
/// but root can put something else there, the restriction is lifted for
/// everything that person runs — so a pasta that is not root's alone is
/// refused.
fn root_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    for p in path.ancestors() {
        let m = fs::metadata(p).map_err(|e| format!("could not inspect {}: {e}", p.display()))?;
        // A sticky directory lets others add entries, but not replace root's.
        let shared = m.mode() & 0o022 != 0 && !(m.is_dir() && m.mode() & 0o1000 != 0);
        let why = if m.uid() != 0 {
            format!("is owned by uid {}", m.uid())
        } else if shared {
            "can be written by users other than root".to_string()
        } else {
            continue;
        };
        return Err(format!(
            "{} {why}, so the pasta there ({}) could be replaced without root.\n  The profile would let whatever is put at that path create user namespaces, so it is only attached to a pasta that only root can change. The distribution's passt package puts one in /usr/bin.",
            p.display(),
            path.display()
        ));
    }
    Ok(())
}

/// Writes `bytes` to `path` so that the loader, reading the directory at any
/// moment, sees the old file or the new one and never half of either.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let dir = path.parent().unwrap_or(Path::new("/"));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(NAME);
    // A leading dot: the loader skips dot files, so a temporary left behind by
    // a crash is never read as policy.
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let written = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        // 0644 whatever root's umask is: `coverage` reads this file as the user
        // who browses, and one they cannot read looks like no profile at all.
        f.set_permissions(fs::Permissions::from_mode(0o644))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("could not write {}: {e}", path.display())
    })
}

fn indent(s: &str) -> String {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!("  {}", l.trim()))
        .collect::<Vec<_>>()
        .join("\n")
}
