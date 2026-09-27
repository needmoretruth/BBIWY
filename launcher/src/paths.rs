//! Where things live.
//!
//! Every location is derived here, so that no other module guesses one. With
//! the defaults:
//!
//! ```text
//! ~/.local/share/bbiwy/              $BBIWY_HOME, 0700
//!   browser/                         the browser `bbiwy install` put in place
//!   daily/ hardened/ tor/ i2p/ ...   one directory per profile, each 0700
//! ~/.local/bin/bbiwy                 the launcher, where menu entries point
//! ~/.local/share/applications/       bbiwy-<profile>.desktop
//! $XDG_RUNTIME_DIR/bbiwy/            which profiles are running right now
//! ```

use std::path::{Path, PathBuf};

/// An environment variable holding a path. XDG says a relative value is
/// invalid and must be ignored, and the same rule is applied to all of them.
fn env_path(var: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os(var)?);
    if p.is_absolute() {
        Some(p)
    } else {
        None
    }
}

pub fn user_home() -> Result<PathBuf, String> {
    env_path("HOME")
        .ok_or_else(|| "HOME is not set to an absolute path, so there is nowhere to keep profiles.".into())
}

fn data_home() -> Result<PathBuf, String> {
    match env_path("XDG_DATA_HOME") {
        Some(p) => Ok(p),
        None => Ok(user_home()?.join(".local/share")),
    }
}

/// Where profiles and the browser live.
pub fn home() -> Result<PathBuf, String> {
    if let Some(v) = std::env::var_os("BBIWY_HOME").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(v);
        if !p.is_absolute() {
            return Err("BBIWY_HOME must be an absolute path.".into());
        }
        return Ok(p);
    }
    Ok(data_home()?.join("bbiwy"))
}

/// The directory of one profile. Its *name* is what the lock file reads to
/// decide which set of locks applies, so it is always exactly the profile name.
pub fn profile_dir(name: &str) -> Result<PathBuf, String> {
    Ok(home()?.join(name))
}

/// The browser `bbiwy install` puts in place — or a symlink to one it adopted.
pub fn browser_root() -> Result<PathBuf, String> {
    Ok(home()?.join("browser"))
}

pub fn applications_dir() -> Result<PathBuf, String> {
    Ok(data_home()?.join("applications"))
}

pub fn bin_dir() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".local/bin"))
}

/// Per-session state. Cleared at logout when it lives in `XDG_RUNTIME_DIR`;
/// anything left behind elsewhere is recognised as stale by its dead pid.
pub fn runtime_dir() -> Result<PathBuf, String> {
    match env_path("XDG_RUNTIME_DIR") {
        Some(p) => Ok(p.join("bbiwy")),
        None => Ok(home()?.join(".run")),
    }
}

/// Creates `dir`, and its parents, and makes sure `dir` itself is private.
///
/// A profile holds cookies, saved logins and history. The default umask would
/// leave it readable by every other account on the machine.
pub fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if !dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    }
    // One that already existed may predate this; tighten it rather than trust it.
    let mode = std::fs::metadata(dir)
        .map_err(|e| format!("could not read {}: {e}", dir.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("could not make {} private: {e}", dir.display()))?;
    }
    Ok(())
}
