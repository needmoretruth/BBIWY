//! `bbiwy install` and `bbiwy uninstall`.
//!
//! Installing is four steps, each of which can be checked by reading it:
//!
//! 1. **Get the browser.** The latest Mullvad Browser release from
//!    cdn.mullvad.net — or a tarball already on disk, or an already extracted
//!    browser, adopted where it is.
//! 2. **Verify it** before anything is unpacked. The tarball's OpenPGP
//!    signature must be good and made by the Tor Browser Developers key, which
//!    is pinned here by fingerprint: a keyserver is never what is trusted.
//! 3. **Lock it down.** The preference locks (`prefs.rs`) and the theme
//!    (`theme.rs`) go into the browser's own directory, and a record of what
//!    was installed goes next to them (`browser.rs`).
//! 4. **Make it reachable.** The launcher is copied to `~/.local/bin`, and each
//!    route gets a menu entry.
//!
//! None of it needs root. The browser lives in the user's home and belongs to
//! the user — which is also what lets it keep itself updated. When it does, it
//! replaces omni.ja and the theme with it; `bbiwy run` notices and puts the
//! theme back before the next window opens (`ensure_current`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::browser::{self, Drift, Install, Stamp, BINARY_IN_ROOT, STAMP_FILE};
use crate::profile::{Ports, PROFILES};
use crate::{apparmor, out, paths, prefs, status, sys, theme};

pub struct Options {
    /// A tarball to install instead of downloading one. Its `.asc` must sit
    /// next to it.
    pub from: Option<PathBuf>,
    /// An already extracted Mullvad Browser to adopt in place.
    pub browser: Option<PathBuf>,
    /// Ports given on the command line. Routes not named keep the port of the
    /// existing installation, or the table's default.
    pub ports: Ports,
    /// Download the latest release even if a browser is installed.
    pub reinstall: bool,
    /// Create menu entries.
    pub desktop: bool,
}

/// The Tor Browser Developers signing key. Mullvad Browser is built and signed
/// by the Tor Project's release process, with this key.
const KEY: &str = include_str!("../keys/torbrowser-developers.asc");

/// Its primary fingerprint. This, not the key file and not a keyserver, is what
/// is trusted: a signature counts only if gpg reports it valid *and* made by a
/// key whose primary fingerprint is exactly this.
const PIN: &str = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

/// Where a newer copy of the key comes from, when the one above predates the
/// subkey a release was signed with. What is fetched is held to the same pin.
const KEY_URL: &str =
    "https://keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

/// The release index for Linux x86_64: version, tarball and signature URLs.
const INDEX: &str =
    "https://cdn.mullvad.net/browser/update_responses/update_1/release/download-linux-x86_64.json";

/// Every URL taken from the index has to be under this.
const CDN: &str = "https://cdn.mullvad.net/browser/";

/// A private working directory in BBIWY_HOME, removed however the work ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Result<Scratch, String> {
        let p = paths::home()?.join(format!(".{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        paths::private_dir(&p)?;
        Ok(Scratch(p))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn at_root(root: &Path) -> Install {
    Install {
        binary: root.join(BINARY_IN_ROOT),
        dir: root.join("Browser"),
    }
}

fn running_profiles() -> Vec<&'static str> {
    PROFILES
        .iter()
        .filter(|p| status::running(p.name).is_some())
        .map(|p| p.name)
        .collect()
}

pub fn install(o: &Options) -> Result<(), String> {
    if sys::euid() == Some(0) {
        return Err("`bbiwy install` needs no root, and should not have it: the browser has to belong to the user who browses, or it can neither run nor update itself. Run it as that user.".into());
    }
    let home = paths::home()?;
    paths::private_dir(&home)?;
    let root = paths::browser_root()?;
    let existing = at_root(&root);

    // Read before anything is replaced: a port chosen once stays chosen.
    let mut ports = existing
        .stamp()
        .ok()
        .flatten()
        .map(|s| s.ports)
        .unwrap_or_default();
    for (name, port) in o.ports.iter_pairs() {
        ports.set(name, port)?;
    }

    let replacing = o.browser.is_some() || o.from.is_some() || o.reinstall || !existing.binary.is_file();
    if replacing {
        let busy = running_profiles();
        if !busy.is_empty() {
            return Err(format!(
                "close the running profiles first ({}): their browser is about to be replaced.",
                busy.join(", ")
            ));
        }
    }

    let inst = if let Some(dir) = &o.browser {
        adopt(dir, &root)?
    } else if let Some(tar) = &o.from {
        let tar = fs::canonicalize(tar).map_err(|e| format!("{}: {e}", tar.display()))?;
        let mut sig = tar.clone().into_os_string();
        sig.push(".asc");
        let sig = PathBuf::from(sig);
        if !sig.is_file() {
            return Err(format!(
                "{} is not there. The signature has to sit next to the tarball; nothing is installed unverified.",
                sig.display()
            ));
        }
        verify(&tar, &sig)?;
        unpack(&tar, &root)?
    } else if existing.binary.is_file() && !o.reinstall {
        out::note(&format!(
            "Keeping Mullvad Browser {} already in {} (it updates itself; `--reinstall` fetches a fresh copy).",
            existing.version(),
            root.display()
        ));
        existing
    } else {
        let dl = Scratch::new("download")?;
        let (tar, sig, version) = download(dl.path())?;
        verify(&tar, &sig)?;
        out::note(&format!("Signature good. Unpacking Mullvad Browser {version}…"));
        unpack(&tar, &root)?
    };

    let stamp = apply(&inst, &ports)?;
    let launcher = install_self()?;
    let entries = if o.desktop { desktop(&inst, &launcher)? } else { 0 };
    summary(&inst, &stamp, &launcher, entries)
}

/// Uses a Mullvad Browser that is already extracted, where it is.
fn adopt(dir: &Path, root: &Path) -> Result<Install, String> {
    let dir = fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let base = if dir.join(BINARY_IN_ROOT).is_file() {
        dir
    } else if dir.join("mullvadbrowser").is_file() && dir.file_name().is_some_and(|n| n == "Browser") {
        dir.parent().map(Path::to_path_buf).unwrap_or(dir)
    } else {
        return Err(format!(
            "{} is not a Mullvad Browser: there is no {BINARY_IN_ROOT} in it.",
            dir.display()
        ));
    };
    if !sys::writable(&base.join("Browser")) {
        return Err(format!(
            "{} is not writable by you. BBIWY puts its locks and theme into the browser's own directory, and a browser you cannot write to cannot update itself either.",
            base.join("Browser").display()
        ));
    }
    match fs::symlink_metadata(root) {
        Ok(m) if m.file_type().is_symlink() => {
            fs::remove_file(root).map_err(|e| format!("could not replace {}: {e}", root.display()))?;
        }
        Ok(_) => {
            if fs::canonicalize(root).ok().as_deref() == Some(base.as_path()) {
                return Ok(at_root(root));
            }
            return Err(format!(
                "a downloaded browser is already installed in {}. Run `bbiwy uninstall` first, then adopt this one.",
                root.display()
            ));
        }
        Err(_) => {}
    }
    std::os::unix::fs::symlink(&base, root)
        .map_err(|e| format!("could not link {} to {}: {e}", root.display(), base.display()))?;
    out::note(&format!("Adopted the browser in {}.", base.display()));
    Ok(at_root(root))
}

fn curl() -> Result<PathBuf, String> {
    sys::tool("curl").ok_or_else(|| "curl is not installed; it downloads the browser.".to_string())
}

/// Fetches the latest release and its signature into `work`.
fn download(work: &Path) -> Result<(PathBuf, PathBuf, String), String> {
    let arch = std::env::consts::ARCH;
    if arch != "x86_64" {
        return Err(format!(
            "Mullvad publishes its browser for Linux on x86_64 only, and this machine is {arch}. With a build of your own: `bbiwy install --browser <dir>`."
        ));
    }
    let curl = curl()?;
    let o = Command::new(&curl)
        .args(["--proto", "=https", "--tlsv1.2", "-fsSL", "--max-time", "60", INDEX])
        .output()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "could not read the release index ({INDEX}): {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    let index = String::from_utf8_lossy(&o.stdout);
    let field = |k: &str| {
        sys::json_str(&index, k).ok_or_else(|| format!("the release index has no \"{k}\"; its format may have changed."))
    };
    let version = field("version")?;
    let binary = field("binary")?;
    let sig = field("sig")?;

    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("the release index names an odd version: {version}"));
    }
    let name = |url: &str| -> Result<String, String> {
        let file = url
            .strip_prefix(CDN)
            .and_then(|rest| rest.rsplit('/').next())
            .filter(|f| !f.is_empty() && !f.starts_with('.') && !url.contains(".."))
            .ok_or_else(|| format!("the release index points outside {CDN}: {url}"))?;
        Ok(file.to_string())
    };
    let tar_name = name(&binary)?;
    let sig_name = name(&sig)?;
    if !tar_name.ends_with(".tar.xz") || sig_name != format!("{tar_name}.asc") {
        return Err(format!("the release index does not describe a signed tarball: {binary}, {sig}"));
    }

    out::note(&format!("Downloading Mullvad Browser {version} from {CDN}"));
    let tar = work.join(&tar_name);
    let sig_file = work.join(&sig_name);
    for (url, dest, bar) in [(&binary, &tar, true), (&sig, &sig_file, false)] {
        let st = Command::new(&curl)
            .args(["--proto", "=https", "--tlsv1.2", "-fL", "--retry", "2"])
            .arg(if bar { "--progress-bar" } else { "-sS" })
            .arg("-o")
            .arg(dest)
            .arg(url)
            .status()
            .map_err(|e| format!("could not run curl: {e}"))?;
        if !st.success() {
            return Err(format!("could not download {url}"));
        }
    }
    Ok((tar, sig_file, version))
}

enum Sig {
    Good,
    /// The key in hand cannot check it: missing or expired subkey.
    NeedsKey(String),
    Bad(String),
}

fn gpg() -> Result<PathBuf, String> {
    sys::tool("gpg").ok_or_else(|| {
        "gpg is not installed; it checks the browser's signature before anything is unpacked.".to_string()
    })
}

fn gpg_import(gpg: &Path, home: &Path, key: &Path) -> Result<(), String> {
    let o = Command::new(gpg)
        .arg("--homedir")
        .arg(home)
        .args(["--batch", "--no-tty", "--quiet", "--no-autostart", "--import"])
        .arg(key)
        .output()
        .map_err(|e| format!("could not run gpg: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "gpg could not import the signing key: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(())
}

fn gpg_verify(gpg: &Path, home: &Path, tar: &Path, sig: &Path) -> Result<Sig, String> {
    let o = Command::new(gpg)
        .arg("--homedir")
        .arg(home)
        .args(["--batch", "--no-tty", "--no-autostart", "--status-fd", "1", "--verify"])
        .arg(sig)
        .arg(tar)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("could not run gpg: {e}"))?;
    let status = String::from_utf8_lossy(&o.stdout).into_owned();
    let tokens = |line: &str| -> Vec<String> {
        line.strip_prefix("[GNUPG:] ")
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    let lines: Vec<Vec<String>> = status.lines().map(tokens).filter(|t| !t.is_empty()).collect();
    let has = |k: &str| lines.iter().any(|t| t[0] == k);
    let pinned = lines
        .iter()
        .any(|t| t[0] == "VALIDSIG" && t.last().is_some_and(|f| f.eq_ignore_ascii_case(PIN)));
    let shown = status
        .lines()
        .filter(|l| !l.contains("KEY_CONSIDERED") && !l.contains("NEWSIG"))
        .collect::<Vec<_>>()
        .join("\n  ");

    Ok(if has("BADSIG") {
        Sig::Bad(shown)
    } else if has("GOODSIG") && pinned {
        Sig::Good
    } else if has("NO_PUBKEY") || has("EXPKEYSIG") || has("KEYEXPIRED") || has("ERRSIG") {
        Sig::NeedsKey(shown)
    } else {
        Sig::Bad(shown)
    })
}

/// Refuses anything that is not signed by the pinned key.
fn verify(tar: &Path, sig: &Path) -> Result<(), String> {
    let gpg = gpg()?;
    let work = Scratch::new("gnupg")?;
    let key = work.path().join("torbrowser-developers.asc");
    fs::write(&key, KEY).map_err(|e| format!("could not write the key: {e}"))?;
    gpg_import(&gpg, work.path(), &key)?;
    let first = gpg_verify(&gpg, work.path(), tar, sig)?;
    let result = match first {
        Sig::NeedsKey(_) => {
            out::note("The signing key carried by this launcher cannot check this release (a newer subkey?). Fetching the current key; it is held to the same pinned fingerprint.");
            let fresh = work.path().join("fresh.asc");
            let st = Command::new(curl()?)
                .args(["--proto", "=https", "--tlsv1.2", "-fsSL", "--max-time", "60", "-o"])
                .arg(&fresh)
                .arg(KEY_URL)
                .status()
                .map_err(|e| format!("could not run curl: {e}"))?;
            if !st.success() {
                return Err(format!("could not fetch the current signing key from {KEY_URL}"));
            }
            gpg_import(&gpg, work.path(), &fresh)?;
            gpg_verify(&gpg, work.path(), tar, sig)?
        }
        other => other,
    };
    match result {
        Sig::Good => Ok(()),
        Sig::NeedsKey(s) | Sig::Bad(s) => Err(format!(
            "the signature on {} does not check out against the Tor Browser Developers key ({PIN}), so nothing was installed.\n  {s}",
            tar.display()
        )),
    }
}

/// Unpacks a verified tarball and puts it in place of any browser before it.
fn unpack(tar: &Path, root: &Path) -> Result<Install, String> {
    let tar_bin = sys::tool("tar").ok_or("tar is not installed")?;
    if sys::tool("xz").is_none() {
        return Err("xz is not installed; the browser comes as a .tar.xz.".into());
    }
    let staging = Scratch::new("install")?;
    let st = Command::new(tar_bin)
        .arg("-xJf")
        .arg(tar)
        .arg("-C")
        .arg(staging.path())
        .status()
        .map_err(|e| format!("could not run tar: {e}"))?;
    if !st.success() {
        return Err(format!("could not unpack {}", tar.display()));
    }
    // The portable build writes a Data/ directory next to Browser/ on its first
    // start, and hangs at startup if it cannot — so the tree must belong to the
    // user who runs it. An extraction by that user does.
    let extracted = staging.path().join("mullvad-browser");
    if !extracted.join(BINARY_IN_ROOT).is_file() {
        return Err(format!(
            "{} does not contain mullvad-browser/{BINARY_IN_ROOT}; it is not a Mullvad Browser for Linux.",
            tar.display()
        ));
    }

    let old = root.with_file_name(format!(".browser-old-{}", std::process::id()));
    match fs::symlink_metadata(root) {
        // An adopted browser: only the link goes; the browser stays where it is.
        Ok(m) if m.file_type().is_symlink() => {
            fs::remove_file(root).map_err(|e| format!("could not replace {}: {e}", root.display()))?;
        }
        Ok(_) => fs::rename(root, &old).map_err(|e| format!("could not move {} aside: {e}", root.display()))?,
        Err(_) => {}
    }
    if let Err(e) = fs::rename(&extracted, root) {
        if old.exists() {
            let _ = fs::rename(&old, root);
        }
        return Err(format!("could not put the browser in {}: {e}", root.display()));
    }
    if old.exists() {
        if let Err(e) = fs::remove_dir_all(&old) {
            out::note(&format!("The previous browser is left in {}: {e}", old.display()));
        }
    }
    Ok(at_root(root))
}

fn write_locks(inst: &Install, ports: &Ports) -> Result<(), String> {
    let cfg = inst.dir.join(prefs::CFG_FILE);
    fs::write(&cfg, prefs::autoconfig(ports)).map_err(|e| format!("could not write {}: {e}", cfg.display()))?;
    let loader = inst.dir.join(prefs::LOADER_FILE);
    if let Some(parent) = loader.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    fs::write(&loader, prefs::LOADER).map_err(|e| format!("could not write {}: {e}", loader.display()))
}

fn new_stamp(inst: &Install, ports: &Ports) -> Stamp {
    Stamp {
        schema: prefs::SCHEMA,
        launcher: env!("CARGO_PKG_VERSION").to_string(),
        browser: inst.version(),
        ports: ports.explicit(),
        theme: browser::omni_fingerprint(&inst.dir),
    }
}

/// Writes the locks and the theme into a browser, and records it.
pub fn apply(inst: &Install, ports: &Ports) -> Result<Stamp, String> {
    write_locks(inst, ports)?;
    theme::apply(&inst.dir)?;
    let stamp = new_stamp(inst, ports);
    inst.write_stamp(&stamp)?;
    Ok(stamp)
}

/// Brings an installation in line with this launcher before a profile starts.
///
/// Two things drift. The launcher is upgraded, and writes different locks. Or
/// the browser updates itself, which replaces omni.ja and the theme with it.
/// Both are repaired here when the installation can be written to; otherwise
/// nothing starts, because a browser whose locks are not the launcher's is not
/// one the launcher can vouch for.
pub fn ensure_current(inst: &Install) -> Result<Stamp, String> {
    let (stamp, drift) = inst.check()?;
    if drift.is_empty() {
        return Ok(stamp);
    }
    if !sys::writable(&inst.dir) {
        return Err(format!(
            "the browser in {} is out of date for this launcher, and you cannot write to it. Whoever installed it has to run `bbiwy install` again.",
            inst.dir.display()
        ));
    }
    if drift.contains(&Drift::Locks) {
        write_locks(inst, &stamp.ports)?;
        out::note(&format!(
            "Rewrote the preference locks for launcher {}.",
            env!("CARGO_PKG_VERSION")
        ));
    }
    if drift.contains(&Drift::Theme) {
        theme::apply(&inst.dir)?;
        out::note(&format!(
            "The browser has changed (it is now {}); put BBIWY's theme back.",
            inst.version()
        ));
    }
    let fresh = new_stamp(inst, &stamp.ports);
    inst.write_stamp(&fresh)?;
    Ok(fresh)
}

/// Copies the launcher to `~/.local/bin`, where menu entries can rely on it.
fn install_self() -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let bin = paths::bin_dir()?;
    let dest = bin.join("bbiwy");
    let me = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    if dest.exists() && fs::canonicalize(&me).ok() == fs::canonicalize(&dest).ok() {
        return Ok(dest);
    }
    fs::create_dir_all(&bin).map_err(|e| format!("could not create {}: {e}", bin.display()))?;
    let tmp = bin.join(format!(".bbiwy.tmp-{}", std::process::id()));
    fs::copy(&me, &tmp).map_err(|e| format!("could not copy the launcher to {}: {e}", bin.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("could not make {} executable: {e}", tmp.display()))?;
    // A rename, so that a profile running from the old copy keeps its file.
    fs::rename(&tmp, &dest).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("could not put the launcher in {}: {e}", dest.display())
    })?;
    Ok(dest)
}

/// A path as a desktop entry's Exec key wants it (Desktop Entry spec, "The Exec
/// key"): quoted when it has to be, and `%` doubled.
fn exec_arg(s: &str) -> String {
    let s = s.replace('%', "%%");
    if s.chars().any(|c| c.is_whitespace() || "\"'\\><~|&;$*?#()`".contains(c)) {
        let mut q = String::from("\"");
        for c in s.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                q.push('\\');
            }
            q.push(c);
        }
        q.push('"');
        q
    } else {
        s
    }
}

/// One menu entry per route that can be started. Returns how many.
fn desktop(inst: &Install, launcher: &Path) -> Result<usize, String> {
    let apps = paths::applications_dir()?;
    fs::create_dir_all(&apps).map_err(|e| format!("could not create {}: {e}", apps.display()))?;
    let icon = inst.dir.join("browser/chrome/icons/default/default128.png");
    let mut made = 0;
    for p in PROFILES {
        let file = apps.join(format!("bbiwy-{}.desktop", p.name));
        if !p.ready {
            let _ = fs::remove_file(&file);
            continue;
        }
        let mut text = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Version=1.0\n\
             Name=BBIWY — {title}\n\
             GenericName=Web Browser\n\
             Comment={about} Sealed in its own network namespace.\n\
             Exec={exec} run {name} %u\n\
             Terminal=false\n\
             Categories=Network;WebBrowser;\n\
             StartupNotify=true\n\
             StartupWMClass=bbiwy-{name}\n",
            title = p.title,
            about = p.about,
            exec = exec_arg(&launcher.to_string_lossy()),
            name = p.name,
        );
        if icon.is_file() {
            text.push_str(&format!("Icon={}\n", icon.display()));
        }
        fs::write(&file, text).map_err(|e| format!("could not write {}: {e}", file.display()))?;
        made += 1;
    }
    if let Some(update) = sys::tool("update-desktop-database") {
        let _ = Command::new(update)
            .arg(&apps)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    Ok(made)
}

fn on_path(dir: &Path) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d == dir))
        .unwrap_or(false)
}

fn summary(inst: &Install, stamp: &Stamp, launcher: &Path, entries: usize) -> Result<(), String> {
    out::line(&format!(
        "Installed Mullvad Browser {} in {}, locked down for BBIWY.",
        stamp.browser,
        inst.root().display()
    ))?;
    out::line("")?;
    for p in PROFILES.iter().filter(|p| p.ready) {
        let state = match p.relay(&stamp.ports) {
            None => String::new(),
            Some(r) if sys::tcp_listener(r.port()).is_some_and(|l| l.takes_v4()) => {
                format!("{} is listening", p.daemon.unwrap_or("relay"))
            }
            Some(_) => format!("{} is not running yet", p.daemon.unwrap_or("relay")),
        };
        out::line(&format!(
            "  {} {} {} {state}",
            p.glyph,
            out::pad(p.name, 9),
            out::pad(&p.route(&stamp.ports), 23)
        ))?;
    }
    out::line("")?;
    out::line(&format!("Launcher: {}", launcher.display()))?;
    if entries > 0 {
        out::line(&format!("Menu entries: {entries}, named \"BBIWY — …\"."))?;
    }
    let bin = launcher.parent().unwrap_or(Path::new("/"));
    if !on_path(bin) {
        out::line(&format!(
            "{} is not on your PATH; add it, or call the launcher by its full path.",
            bin.display()
        ))?;
    }
    out::line("")?;
    out::line("Next:")?;
    if matches!(apparmor::coverage(), apparmor::Coverage::Missing) {
        out::line(&format!(
            "  sudo {} apparmor     once: this system restricts user namespaces",
            launcher.display()
        ))?;
    }
    out::line("  bbiwy doctor         does isolation hold on this machine?")?;
    out::line("  bbiwy run daily      and the other routes: hardened, tor, i2p")
}

pub fn uninstall(purge: bool) -> Result<(), String> {
    if sys::euid() == Some(0) {
        return Err("run `bbiwy uninstall` as the user it was installed for.".into());
    }
    let busy = running_profiles();
    if !busy.is_empty() {
        return Err(format!("close the running profiles first: {}.", busy.join(", ")));
    }
    let home = paths::home()?;
    let mut gone: Vec<String> = Vec::new();

    let apps = paths::applications_dir()?;
    for p in PROFILES {
        let f = apps.join(format!("bbiwy-{}.desktop", p.name));
        if fs::remove_file(&f).is_ok() {
            gone.push(f.display().to_string());
        }
    }

    let root = paths::browser_root()?;
    match fs::symlink_metadata(&root) {
        Ok(m) if m.file_type().is_symlink() => {
            // An adopted browser is someone else's: give it back as it came.
            if let Ok(target) = fs::canonicalize(&root) {
                let dir = target.join("Browser");
                theme::remove(&dir)?;
                for f in [prefs::CFG_FILE, prefs::LOADER_FILE, STAMP_FILE] {
                    let _ = fs::remove_file(dir.join(f));
                }
                gone.push(format!(
                    "BBIWY's theme and locks from {} (the browser itself stays)",
                    target.display()
                ));
            }
            fs::remove_file(&root).map_err(|e| format!("could not remove {}: {e}", root.display()))?;
        }
        Ok(_) => {
            fs::remove_dir_all(&root).map_err(|e| format!("could not remove {}: {e}", root.display()))?;
            gone.push(root.display().to_string());
        }
        Err(_) => {}
    }

    let copy = paths::bin_dir()?.join("bbiwy");
    if fs::remove_file(&copy).is_ok() {
        gone.push(copy.display().to_string());
    }

    if purge {
        for p in PROFILES {
            let d = home.join(p.name);
            if d.is_dir() {
                fs::remove_dir_all(&d).map_err(|e| format!("could not remove {}: {e}", d.display()))?;
                gone.push(d.display().to_string());
            }
        }
        let _ = fs::remove_dir_all(home.join(".run"));
        if let Ok(rt) = paths::runtime_dir() {
            let _ = fs::remove_dir_all(rt);
        }
        if fs::remove_dir(&home).is_ok() {
            gone.push(home.display().to_string());
        }
    }

    if gone.is_empty() {
        out::line("Nothing to remove.")?;
    } else {
        out::line("Removed:")?;
        for g in &gone {
            out::line(&format!("  {g}"))?;
        }
    }
    if !purge {
        let kept: Vec<&str> = PROFILES
            .iter()
            .filter(|p| home.join(p.name).is_dir())
            .map(|p| p.name)
            .collect();
        if !kept.is_empty() {
            out::line(&format!(
                "Kept the profiles ({}) in {}. `bbiwy uninstall --purge` deletes them.",
                kept.join(", "),
                home.display()
            ))?;
        }
    }
    if Path::new("/etc/apparmor.d/bbiwy").exists() {
        out::line("The AppArmor profile needs root to remove: sudo apparmor_parser -R /etc/apparmor.d/bbiwy && sudo rm /etc/apparmor.d/bbiwy")?;
    }
    Ok(())
}
