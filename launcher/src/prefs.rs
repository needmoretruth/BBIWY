//! What each profile's browser is told — and how it is held there.
//!
//! Two layers, and this is the first. The allow-list in the namespace is the
//! one that cannot be argued with; this one exists so that the browser never
//! even tries what the allow-list would drop. A browser that tries and is
//! stopped shows up in the counters, and counters that fill with the browser's
//! own routine noise stop meaning anything.
//!
//! The values are held by Gecko's autoconfig: one file, installed next to the
//! browser, that picks a block by the **name of the profile directory** at
//! startup. Never by the environment — a user can set a variable, and a lock a
//! variable can lift is not a lock (MEASUREMENTS §8). The environment is read
//! for one thing only, and only in the direction of taking away: a window that
//! was not started by the launcher does not claim a route.

use std::path::Path;

use crate::profile::{Ports, Profile, Relay, Strictness, PROFILES};

/// Bumped whenever the lock file changes meaning. An installation written for
/// another schema is rewritten before anything starts.
pub const SCHEMA: u32 = 1;

/// The lock file, in the browser's installation directory.
pub const CFG_FILE: &str = "bbiwy.cfg";

/// The default-preferences file that points Gecko at it.
pub const LOADER_FILE: &str = "defaults/pref/bbiwy-autoconfig.js";

pub const LOADER: &str = "\
// BBIWY: have Gecko read bbiwy.cfg, the preference locks, at startup.
// Written by `bbiwy install`.
pref(\"general.config.filename\", \"bbiwy.cfg\");
pref(\"general.config.obscure_value\", 0);
// The locks decide which profile they are in from the profile directory, and
// only an unsandboxed autoconfig can see it (MEASUREMENTS §8).
pref(\"general.config.sandbox_enabled\", false);
";

/// Mullvad's resolver — the base browser's own default, kept.
const DOH_URI: &str = "https://dns.mullvad.net/dns-query";

/// Its address. Inside the namespace there is no cleartext DNS to ask where the
/// resolver is, so it is reached by address.
const DOH_BOOTSTRAP: &str = "194.242.2.2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}
impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Value::Int(i64::from(v))
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Str(v.to_string())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Str(v)
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.js())
    }
}

impl Value {
    fn js(&self) -> String {
        match self {
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Str(s) => js_str(s),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pref {
    pub name: String,
    pub value: Value,
    /// Locked: nothing in the profile can change it. Otherwise it is a default
    /// the user may override.
    pub locked: bool,
}

/// A preference set in the order it is written, with the reasons in between.
#[derive(Default)]
struct Set(Vec<Entry>);

enum Entry {
    Note(&'static str),
    Pref(Pref),
}

impl Set {
    fn note(&mut self, s: &'static str) {
        self.0.push(Entry::Note(s));
    }
    fn lock(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.put(name.into(), value.into(), true);
    }
    fn dflt(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.put(name.into(), value.into(), false);
    }
    fn put(&mut self, name: String, value: Value, locked: bool) {
        self.0.push(Entry::Pref(Pref { name, value, locked }));
    }
    fn prefs(self) -> Vec<Pref> {
        self.0
            .into_iter()
            .filter_map(|e| match e {
                Entry::Pref(p) => Some(p),
                Entry::Note(_) => None,
            })
            .collect()
    }
}

/// Every profile, and a profile the launcher does not know.
fn common(s: &mut Set) {
    s.note("UDP never leaves the namespace. HTTP/3 would try, be dropped, and fill the counters with the browser's own noise; h2 against h3 is also something a server could tell profiles apart by.");
    s.lock("network.http.http3.enable", false);
    s.note("GIO fetches through gvfs, a process outside the namespace.");
    s.lock("network.gio.supported-protocols", "");
    s.note("No quiet way around a configured route, even when it is down.");
    s.lock("network.proxy.failover_direct", false);
    s.lock("network.proxy.allow_bypass", false);
    s.note("Nothing opens a connection before the page asks for one.");
    s.lock("network.dns.disablePrefetch", true);
    s.lock("network.dns.disablePrefetchFromHTTPS", true);
    s.lock("network.prefetch-next", false);
    s.lock("network.predictor.enabled", false);
    s.lock("network.http.speculative-parallel-limit", 0i64);
    s.lock("browser.urlbar.speculativeConnect.enabled", false);
    s.note("Background probes that could only ever be dropped.");
    s.lock("network.captive-portal-service.enabled", false);
    s.lock("network.connectivity-service.enabled", false);
    s.note("One fingerprint for all five (MEASUREMENTS §9).");
    s.lock("privacy.resistFingerprinting", true);
    s.note("WebRTC stays on: turning it off was the only change that made profiles distinguishable (MEASUREMENTS §2). It only ever goes through the route.");
    s.lock("media.peerconnection.ice.no_host", true);
    s.lock("media.peerconnection.ice.default_address_only", true);
    s.lock("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
    s.note(".onion names are never looked up outside Tor.");
    s.lock("network.dns.blockDotOnion", true);
    s.note("A name that only means something on one route is an address, not a search: typed into the wrong profile it goes nowhere, rather than to a search engine.");
    for p in PROFILES {
        if let Some(suffix) = p.suffix {
            s.lock(
                format!("browser.fixup.domainsuffixwhitelist.{}", suffix.trim_start_matches('.')),
                true,
            );
        }
    }
}

fn strict(s: &mut Set) {
    s.note("Strict: nothing persists.");
    s.lock("browser.privatebrowsing.autostart", true);
    s.lock("signon.rememberSignons", false);
    s.lock("browser.formfill.enable", false);
    s.lock("privacy.resistFingerprinting.letterboxing", true);
}

fn relaxed(s: &mut Set) {
    s.note("Daily: logins, history and form data persist, measured to cost no fingerprint difference (MEASUREMENTS §9). Defaults rather than locks: this is the profile where the user decides.");
    s.dflt("browser.privatebrowsing.autostart", false);
    s.dflt("signon.rememberSignons", true);
    s.dflt("browser.formfill.enable", true);
    s.dflt("places.history.enabled", true);
    s.dflt("privacy.sanitize.sanitizeOnShutdown", false);
    s.note("Letterboxing on, as everywhere; only here can it be turned off. Off, the exact window size goes out (MEASUREMENTS §9).");
    s.dflt("privacy.resistFingerprinting.letterboxing", true);
}

fn direct(s: &mut Set) {
    s.note("Direct: no proxy, and names resolved only over HTTPS. Port 53 is dropped in the namespace, so the resolver is reached by address.");
    s.lock("network.proxy.type", 0i64);
    s.lock("network.trr.mode", 3i64);
    s.dflt("network.trr.uri", DOH_URI);
    s.dflt("network.trr.bootstrapAddr", DOH_BOOTSTRAP);
    // The names of the other routes, other than .onion (blocked above).
    let others: Vec<&str> = PROFILES
        .iter()
        .filter_map(|p| p.suffix)
        .filter(|s| *s != ".onion")
        .map(|s| s.trim_start_matches('.'))
        .collect();
    if !others.is_empty() {
        s.note("Names of the other routes are never sent to the resolver. They are left to the system resolver, which the namespace drops, and show up as counted DNS attempts.");
        s.dflt("network.trr.excluded-domains", others.join(","));
    }
}

fn proxied(s: &mut Set, relay: Relay) {
    s.note("Proxied: everything, names included, through the relay on 127.0.0.1. Nothing is resolved here.");
    s.lock("network.proxy.type", 1i64);
    match relay {
        Relay::Socks5(port) => {
            s.lock("network.proxy.socks", "127.0.0.1");
            s.lock("network.proxy.socks_port", port);
            s.lock("network.proxy.socks_version", 5i64);
            s.note("Both: Firefox 128 split them. With socks5_remote_dns off, 6 DNS packets escaped (MEASUREMENTS §3).");
            s.lock("network.proxy.socks5_remote_dns", true);
            s.lock("network.proxy.socks_remote_dns", true);
            s.lock("network.proxy.http", "");
            s.lock("network.proxy.http_port", 0i64);
            s.lock("network.proxy.ssl", "");
            s.lock("network.proxy.ssl_port", 0i64);
        }
        Relay::Http(port) => {
            s.lock("network.proxy.http", "127.0.0.1");
            s.lock("network.proxy.http_port", port);
            s.lock("network.proxy.ssl", "127.0.0.1");
            s.lock("network.proxy.ssl_port", port);
            s.lock("network.proxy.socks", "");
            s.lock("network.proxy.socks_port", 0i64);
        }
    }
    s.note("The name reads backwards: true sends localhost through the proxy as well (MEASUREMENTS §3).");
    s.lock("network.proxy.allow_hijacking_localhost", true);
    s.lock("network.proxy.no_proxies_on", "");
    s.note("No DNS over HTTPS: names go to the route.");
    s.lock("network.trr.mode", 5i64);
}

/// What only one route needs, keyed by the suffix it serves.
fn route_specific(s: &mut Set, p: &Profile) {
    match p.suffix {
        Some(".onion") => {
            s.note("Onion services are end-to-end already, and most are plain HTTP; HTTPS-Only would refuse them.");
            s.dflt("dom.security.https_only_mode.upgrade_onion", false);
        }
        Some(".i2p") => {
            s.note("I2P sites are served over HTTP inside I2P's own end-to-end tunnels, and HTTPS-Only would refuse every one of them. HTTPS-First still upgrades what it can.");
            s.dflt("dom.security.https_only_mode", false);
            s.dflt("dom.security.https_only_mode_pbm", false);
            s.dflt("dom.security.https_first", true);
            s.dflt("dom.security.https_first_pbm", true);
        }
        _ => {}
    }
}

fn set_for(p: &Profile, relay: Option<Relay>) -> Set {
    let mut s = Set::default();
    common(&mut s);
    match p.strictness {
        Strictness::Daily => relaxed(&mut s),
        Strictness::Hardened => strict(&mut s),
    }
    match relay {
        None => direct(&mut s),
        Some(r) => proxied(&mut s, r),
    }
    route_specific(&mut s, p);
    s
}

fn set_for_unknown() -> Set {
    let mut s = Set::default();
    common(&mut s);
    strict(&mut s);
    s
}

/// Every value BBIWY sets for a profile, locked or not.
pub fn for_profile(p: &Profile, relay: Option<Relay>) -> Vec<Pref> {
    set_for(p, relay).prefs()
}

fn js_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Wraps a note at about 76 columns as `//` comments at `indent`.
fn comment(out: &mut String, indent: &str, text: &str) {
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + 3 + line.len() + 1 + word.len() > 78 {
            out.push_str(&format!("{indent}// {line}\n"));
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push_str(&format!("{indent}// {line}\n"));
    }
}

fn emit(out: &mut String, set: Set) {
    for e in set.0 {
        match e {
            Entry::Note(n) => {
                out.push('\n');
                comment(out, "    ", n);
            }
            Entry::Pref(p) => out.push_str(&format!(
                "    {}({}, {});\n",
                if p.locked { "lock" } else { "dflt" },
                js_str(&p.name),
                p.value.js()
            )),
        }
    }
}

const HELPERS: &str = r#"
  // lockPref() unlocks, sets the default and locks again. A default the base
  // build locked stays locked until it is unlocked, so dflt() unlocks first —
  // through the service rather than unlockPref(), which raises a modal alert
  // when the pref does not exist yet.
  function lock(name, value) {
    lockPref(name, value);
  }
  function dflt(name, value) {
    try {
      if (Services.prefs.prefIsLocked(name)) Services.prefs.unlockPref(name);
    } catch (e) {}
    defaultPref(name, value);
  }

  // The profile is the directory's name, exactly as the launcher creates it.
  var profile = null;
  try {
    var dir = Components.classes["@mozilla.org/file/directory_service;1"]
      .getService(Components.interfaces.nsIProperties)
      .get("ProfD", Components.interfaces.nsIFile);
    if (ROUTES.indexOf(String(dir.leafName)) !== -1) profile = String(dir.leafName);
  } catch (e) {}

  // Read only to take the route marking away from a window the launcher did
  // not start. It never decides a lock.
  var launched = false;
  try {
    launched = profile !== null && getenv("BBIWY_PROFILE") === profile;
  } catch (e) {}

"#;

const MARKING: &str = r#"
  // The route marking (theme/bbiwy-path.css). Only a window that is in a
  // route's profile *and* was started by the launcher claims that route; every
  // other window claims none. All five are written, so that no leftover value
  // can make a window claim two.
  for (var i = 0; i < ROUTES.length; i++) {
    lock("bbiwy.path." + ROUTES[i], launched && ROUTES[i] === profile);
  }
  lock("bbiwy.lock.profile", profile === null ? "" : profile);

  // Last, so that a file which stopped half-way shows as one: without it the
  // address bar reads UNLOCKED instead of a route.
  lock("bbiwy.lock.complete", true);
"#;

/// The whole lock file. Deterministic for a given launcher version and set of
/// ports, which is what lets `bbiwy run` tell a current installation from a
/// stale one by comparing bytes.
pub fn autoconfig(ports: &Ports) -> String {
    let mut s = String::new();
    s.push_str("// BBIWY preference locks. Gecko discards the first line of this file.\n");
    s.push_str("//\n");
    s.push_str(&format!(
        "// Written by `bbiwy install` (launcher {}, schema {SCHEMA}). Generated from\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str("// launcher/src/prefs.rs; edits here are undone the next time the launcher\n");
    s.push_str("// checks the installation.\n//\n");
    for (name, relay) in ports.resolved() {
        s.push_str(&format!("// route {name}: {relay}\n"));
    }
    s.push_str("//\n");
    s.push_str("// Which block applies is decided by the name of the profile directory. A\n");
    s.push_str("// profile that is not one of BBIWY's gets the strict set and no route.\n\n");
    s.push_str("(function () {\n");
    let names: Vec<String> = PROFILES.iter().map(|p| js_str(p.name)).collect();
    s.push_str(&format!("  var ROUTES = [{}];\n", names.join(", ")));
    s.push_str(HELPERS);
    for (i, p) in PROFILES.iter().enumerate() {
        s.push_str(if i == 0 { "  if " } else { "  } else if " });
        s.push_str(&format!("(profile === {}) {{\n", js_str(p.name)));
        emit(&mut s, set_for(p, p.relay(ports)));
    }
    s.push_str("  } else {\n");
    emit(&mut s, set_for_unknown());
    s.push_str("  }\n");
    s.push_str(MARKING);
    s.push_str("})();\n");
    s
}

/// Writes the route marking into the profile's `user.js`.
///
/// The lock file already locks these, for every window, from the profile's
/// directory name. This copy is what the chrome sees if the lock file is
/// missing or stopped part-way — and then the address bar says UNLOCKED next
/// to it, rather than showing nothing.
///
/// **All five are written, four of them false.** Writing only the true one
/// would be enough on a fresh profile and wrong on a used one: `prefs.js`
/// keeps whatever was set before, and a leftover would leave a window claiming
/// two routes at once.
///
/// The block is fenced. Anything else in `user.js` survives being rewritten.
pub fn write_user_js(dir: &Path, p: &Profile) -> Result<(), String> {
    const BEGIN: &str = "// >>> bbiwy route -- written at every start";
    const END: &str = "// <<< bbiwy route";

    let path = dir.join("user.js");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut kept = String::new();
    let mut inside = false;
    for line in existing.lines() {
        if line == BEGIN {
            inside = true;
        } else if line == END {
            inside = false;
        } else if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }

    kept.push_str(BEGIN);
    kept.push('\n');
    for other in PROFILES {
        kept.push_str(&format!(
            "user_pref(\"bbiwy.path.{}\", {});\n",
            other.name,
            other.name == p.name
        ));
    }
    kept.push_str(END);
    kept.push('\n');

    std::fs::write(&path, kept).map_err(|e| format!("could not write {}: {e}", path.display()))
}
