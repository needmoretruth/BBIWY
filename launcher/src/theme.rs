//! The monochrome theme, put into the browser's omni.ja files.
//!
//! The Rust twin of `tools/theme/apply.sh`: the same four stylesheets, the same
//! three entries, the same marker, the same bytes. Either one, run over the
//! other's result, replaces the block instead of adding a second. The script
//! stays the design loop — it reads the stylesheets from the tree, so a change
//! shows without rebuilding anything — and this is how an installation gets
//! them, from a launcher that carries them inside itself.
//!
//! Nothing is registered or overridden. Each stylesheet is appended to an entry
//! the browser already loads, outside any `@layer`, which is what lets it win
//! over the design system (theme/README.md). An omni.ja is an ordinary zip; one
//! entry is replaced and the other eight thousand are left alone.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{paths, sys};

/// Where BBIWY's block starts. Everything from the first line beginning with
/// it to the end of the entry is BBIWY's; cutting there restores the original.
const MARK: &str = "/* ==== BBIWY ==== */";

const TOKENS: &str = include_str!("../../theme/bbiwy-tokens.css");
const INFOBAR: &str = include_str!("../../theme/bbiwy-infobar.css");
const CHROME: &str = include_str!("../../theme/bbiwy-chrome.css");
const PATH: &str = include_str!("../../theme/bbiwy-path.css");

struct Target {
    /// Relative to the browser's directory.
    jar: &'static str,
    entry: &'static str,
    sheets: &'static [&'static str],
}

const TARGETS: &[Target] = &[
    // The design system: the primitive colour tokens some five thousand var()
    // references bottom out in. Panels, dialogs and in-content pages follow.
    Target {
        jar: "omni.ja",
        entry: "chrome/toolkit/skin/classic/global/design-system/tokens-shared.css",
        sheets: &[TOKENS],
    },
    // Notification bars live in a shadow root the document's rules never
    // reach; their own stylesheet is the only way in.
    Target {
        jar: "omni.ja",
        entry: "chrome/toolkit/content/global/elements/infobar.css",
        sheets: &[INFOBAR],
    },
    // The toolbar, tabs and address bar read their own variables, not the
    // design system's — and this is where the route marking goes.
    Target {
        jar: "browser/omni.ja",
        entry: "chrome/browser/skin/classic/browser/browser-shared.css",
        sheets: &[CHROME, PATH],
    },
];

/// Everything before BBIWY's block, one `\n` after every line — what apply.sh's
/// `awk` leaves, byte for byte.
fn base(entry: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entry.len());
    for line in entry.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(MARK.as_bytes()) {
            break;
        }
        out.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    out
}

fn has_mark(entry: &[u8]) -> bool {
    entry
        .split(|b| *b == b'\n')
        .any(|l| l.starts_with(MARK.as_bytes()))
}

/// What the entry reads once BBIWY's block is on it.
fn patched(entry: &[u8], sheets: &[&str]) -> Vec<u8> {
    let mut out = base(entry);
    out.extend_from_slice(MARK.as_bytes());
    out.push(b'\n');
    for css in sheets {
        out.push(b'\n');
        out.extend_from_slice(css.as_bytes());
    }
    out
}

/// A private working directory, removed however the work ends.
struct Work(PathBuf);

impl Work {
    fn new() -> Result<Work, String> {
        let p = paths::home()?.join(format!(".theme-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        paths::private_dir(&p)?;
        Ok(Work(p))
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tools() -> Result<(PathBuf, PathBuf), String> {
    let zip = sys::tool("zip").ok_or("zip is not installed; the theme goes into the browser's omni.ja, which is a zip.")?;
    let unzip = sys::tool("unzip").ok_or("unzip is not installed; the theme goes into the browser's omni.ja, which is a zip.")?;
    Ok((zip, unzip))
}

fn read_entry(unzip: &Path, jar: &Path, entry: &str) -> Result<Vec<u8>, String> {
    let o = Command::new(unzip)
        .arg("-p")
        .arg(jar)
        .arg(entry)
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run unzip: {e}"))?;
    if !o.status.success() || o.stdout.is_empty() {
        return Err(format!(
            "{} has no {entry}. This browser's layout is not the one BBIWY's theme was made for.",
            jar.display()
        ));
    }
    Ok(o.stdout)
}

fn write_entry(zip: &Path, work: &Work, jar: &Path, entry: &str, bytes: &[u8]) -> Result<(), String> {
    let staged = work.0.join(entry);
    if let Some(parent) = staged.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("could not stage {entry}: {e}"))?;
    }
    std::fs::write(&staged, bytes).map_err(|e| format!("could not stage {entry}: {e}"))?;
    // Run from the work directory, so that the entry keeps its path inside the
    // archive. zip writes a new archive beside the old one and renames it into
    // place, so a browser already running from this one keeps what it mapped.
    let st = Command::new(zip)
        .current_dir(&work.0)
        .arg("-X")
        .arg("-q")
        .arg(jar)
        .arg(entry)
        .status()
        .map_err(|e| format!("could not run zip: {e}"))?;
    if !st.success() {
        return Err(format!("zip could not replace {entry} in {}", jar.display()));
    }
    Ok(())
}

/// Puts the theme into the browser in `dir`. An entry that already reads right
/// is left untouched, so that running this again changes nothing on disk.
pub fn apply(dir: &Path) -> Result<(), String> {
    let (zip, unzip) = tools()?;
    let work = Work::new()?;
    for t in TARGETS {
        let jar = dir.join(t.jar);
        let now = read_entry(&unzip, &jar, t.entry)?;
        let want = patched(&now, t.sheets);
        if want != now {
            write_entry(&zip, &work, &jar, t.entry, &want)?;
        }
    }
    Ok(())
}

/// Takes the theme out again, restoring each entry to how it came.
pub fn remove(dir: &Path) -> Result<(), String> {
    let (zip, unzip) = tools()?;
    let work = Work::new()?;
    for t in TARGETS {
        let jar = dir.join(t.jar);
        if !jar.is_file() {
            continue;
        }
        let now = read_entry(&unzip, &jar, t.entry)?;
        if has_mark(&now) {
            write_entry(&zip, &work, &jar, t.entry, &base(&now))?;
        }
    }
    Ok(())
}
