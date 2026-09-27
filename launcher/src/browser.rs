//! The browser installation: where it is, and whether BBIWY's files in it are
//! the ones this launcher would write.
//!
//! Gecko reads its defaults and its autoconfig from the directory that holds
//! the binary, so that directory is the one everything here is relative to:
//!
//! ```text
//! <root>/Browser/                   `dir`
//!   mullvadbrowser                  `binary` (a wrapper; runs mullvadbrowser.real)
//!   omni.ja  browser/omni.ja        the theme is appended inside these
//!   bbiwy.cfg                       the preference locks        (prefs.rs)
//!   defaults/pref/bbiwy-autoconfig.js   points Gecko at them
//!   bbiwy-install                   what was installed, and with which ports
//! ```

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::profile::Ports;
use crate::{paths, prefs, sys};

pub struct Install {
    /// What the launcher starts.
    pub binary: PathBuf,
    /// The directory holding it — Gecko's application directory.
    pub dir: PathBuf,
}

/// Where the installed Mullvad Browser keeps its binary, under the root.
pub const BINARY_IN_ROOT: &str = "Browser/mullvadbrowser";

/// Future BBIWY builds. Kept so that an installation there keeps working.
const LEGACY: &[&str] = &["/opt/bbiwy/browser/bbiwy", "/usr/lib/bbiwy/bbiwy"];

pub fn locate() -> Result<Install, String> {
    if let Some(v) = std::env::var_os("BBIWY_BROWSER").filter(|v| !v.is_empty()) {
        let binary = PathBuf::from(v);
        if !binary.is_file() {
            return Err(format!("BBIWY_BROWSER points at nothing: {}", binary.display()));
        }
        return Install::at(binary);
    }
    let installed = paths::browser_root()?.join(BINARY_IN_ROOT);
    if installed.is_file() {
        return Install::at(installed);
    }
    for cand in LEGACY {
        if Path::new(cand).is_file() {
            return Install::at(PathBuf::from(cand));
        }
    }
    Err("no browser installed. Run `bbiwy install`.".into())
}

/// The installation record, in `dir`.
pub const STAMP_FILE: &str = "bbiwy-install";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub schema: u32,
    pub launcher: String,
    pub browser: String,
    /// Every proxied route's port, written out.
    pub ports: Ports,
    /// Size and modification time of the omni.ja files after the theme went
    /// in. When the browser updates itself it replaces them, and this is how
    /// that is noticed.
    pub theme: String,
}

impl Stamp {
    pub fn render(&self) -> String {
        let mut s = String::from(
            "# BBIWY installation record. Written by `bbiwy install`; do not edit —\n\
             # run `bbiwy install` again to change it.\n",
        );
        s.push_str(&format!("schema = {}\n", self.schema));
        s.push_str(&format!("launcher = {}\n", self.launcher));
        s.push_str(&format!("browser = {}\n", self.browser));
        for (name, port) in self.ports.explicit().iter_pairs() {
            s.push_str(&format!("port.{name} = {port}\n"));
        }
        s.push_str(&format!("theme = {}\n", self.theme));
        s
    }

    pub fn parse(text: &str) -> Result<Stamp, String> {
        let mut st = Stamp {
            schema: 0,
            launcher: String::new(),
            browser: String::new(),
            ports: Ports::default(),
            theme: String::new(),
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(format!("unreadable line in the installation record: {line}"));
            };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "schema" => st.schema = v.parse().map_err(|_| format!("bad schema: {v}"))?,
                "launcher" => st.launcher = v.to_string(),
                "browser" => st.browser = v.to_string(),
                "theme" => st.theme = v.to_string(),
                _ => {
                    if let Some(name) = k.strip_prefix("port.") {
                        let port = v.parse().map_err(|_| format!("bad port for {name}: {v}"))?;
                        st.ports.set(name, port)?;
                    }
                    // Anything else is from a newer launcher; ignore it.
                }
            }
        }
        Ok(st)
    }
}

/// Something in the installation that does not match this launcher.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Drift {
    /// The lock file or its loader is missing or not what this launcher writes.
    Locks,
    /// omni.ja changed since the theme went in — normally a browser update.
    Theme,
}

impl Install {
    fn at(binary: PathBuf) -> Result<Install, String> {
        let dir = binary
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", binary.display()))?
            .to_path_buf();
        Ok(Install { binary, dir })
    }

    pub fn stamp(&self) -> Result<Option<Stamp>, String> {
        let path = self.dir.join(STAMP_FILE);
        match std::fs::read_to_string(&path) {
            Ok(t) => Stamp::parse(&t).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("could not read {}: {e}", path.display())),
        }
    }

    pub fn write_stamp(&self, s: &Stamp) -> Result<(), String> {
        let path = self.dir.join(STAMP_FILE);
        std::fs::write(&path, s.render()).map_err(|e| format!("could not write {}: {e}", path.display()))
    }

    /// The browser's own version, for messages.
    pub fn version(&self) -> String {
        if let Ok(t) = std::fs::read_to_string(self.dir.join("version.json")) {
            if let Some(v) = sys::json_str(&t, "version") {
                return v;
            }
        }
        if let Ok(t) = std::fs::read_to_string(self.dir.join("application.ini")) {
            if let Some(v) = t.lines().find_map(|l| l.strip_prefix("Version=")) {
                return v.trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Compares the installation with what this launcher would write.
    ///
    /// An installation without a record has never been through `bbiwy install`
    /// — its browser would start with no locks at all — and is an error.
    pub fn check(&self) -> Result<(Stamp, Vec<Drift>), String> {
        let stamp = self.stamp()?.ok_or_else(|| {
            format!(
                "BBIWY is not installed into {}: the browser there has no locks.\n  Run `bbiwy install`{}.",
                self.dir.display(),
                if std::env::var_os("BBIWY_BROWSER").is_some() {
                    format!(" --browser {}", self.root().display())
                } else {
                    String::new()
                }
            )
        })?;
        let mut drift = Vec::new();
        let read = |rel: &str| std::fs::read_to_string(self.dir.join(rel)).ok();
        let locks_current = stamp.schema == prefs::SCHEMA
            && read(prefs::CFG_FILE).as_deref() == Some(prefs::autoconfig(&stamp.ports).as_str())
            && read(prefs::LOADER_FILE).as_deref() == Some(prefs::LOADER);
        if !locks_current {
            drift.push(Drift::Locks);
        }
        if omni_fingerprint(&self.dir) != stamp.theme {
            drift.push(Drift::Theme);
        }
        Ok((stamp, drift))
    }

    /// The directory that holds `Browser/` in the tarball layout, else `dir`.
    pub fn root(&self) -> PathBuf {
        if self.dir.file_name().is_some_and(|n| n == "Browser") {
            if let Some(parent) = self.dir.parent() {
                return parent.to_path_buf();
            }
        }
        self.dir.clone()
    }
}

/// Size and modification time of both omni.ja files.
pub fn omni_fingerprint(dir: &Path) -> String {
    ["omni.ja", "browser/omni.ja"]
        .iter()
        .map(|f| match std::fs::metadata(dir.join(f)) {
            Ok(m) => {
                let t = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| format!("{}.{:09}", d.as_secs(), d.subsec_nanos()))
                    .unwrap_or_default();
                format!("{f}={}@{t}", m.len())
            }
            Err(_) => format!("{f}=missing"),
        })
        .collect::<Vec<_>>()
        .join(";")
}
