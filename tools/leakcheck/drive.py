#!/usr/bin/env python3
"""drive — drive a real browser through geckodriver and measure it.

Three things, none of which are visible by looking:

  locks        whether a pref is genuinely locked. Asks Services.prefs.prefIsLocked
               from chrome scope — the only honest way to ask. This is what
               separates user.js from policies.json from autoconfig.
  leaks        whether an extension calling browser.dns.resolve bypasses the proxy.
               The verdict belongs to the namespace counters, not to this program;
               here we only provoke.
  fingerprint  dumps the surface a page can actually see, for diffing across
               profiles and across browser versions.

Standard library only. Adding selenium would make its version one more variable.
"""
import argparse, json, os, socket, subprocess, sys, time, urllib.request

class WD:
    def __init__(self, port, driver_grants=False):
        self.base = "http://127.0.0.1:%d" % port
        self.sid = None
        # Chrome scope — where lock state is read — has to be granted. geckodriver
        # 0.36 and later grant it themselves when started with
        # --allow-system-access, and 0.37 refuses the browser argument that did
        # it before; older ones know only that argument. start_geckodriver()
        # works out which, and sets this.
        self.driver_grants = driver_grants

    def _req(self, method, path, body=None):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url, data=data, method=method,
                                   headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=120) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:800]
            raise RuntimeError("%s %s -> %d\n%s" % (method, path, e.code, body)) from None

    def start(self, binary, profile, extra_args=None):
        args = ["--profile", profile, "--no-remote"]
        if not self.driver_grants:
            args.append("-remote-allow-system-access")
        caps = {
            "capabilities": {
                "alwaysMatch": {
                    "moz:firefoxOptions": {
                        "binary": binary,
                        "args": args + (extra_args or []),
                        "prefs": {"marionette.enabled": True},
                    },
                    "acceptInsecureCerts": True,
                }
            }
        }
        try:
            self.sid = self._req("POST", "/session", caps)["value"]["sessionId"]
        except RuntimeError as e:
            if self.driver_grants or "can't be set via capabilities" not in str(e):
                raise
            # Said plainly, rather than as the driver's HTTP 400.
            raise RuntimeError(
                "this geckodriver refuses -remote-allow-system-access: it is 0.36 or "
                "later, and grants chrome scope only when started with "
                "--allow-system-access. Start it with drive.start_geckodriver().") from None
        return self.sid

    def ctx(self, which):
        return self._req("POST", "/session/%s/moz/context" % self.sid, {"context": which})

    def script_async(self, src, args=None):
        return self._req("POST", "/session/%s/execute/async" % self.sid,
                         {"script": src, "args": args or []})["value"]

    def script(self, src, args=None):
        return self._req("POST", "/session/%s/execute/sync" % self.sid,
                         {"script": src, "args": args or []})["value"]

    def install(self, path, temporary=True):
        return self._req("POST", "/session/%s/moz/addon/install" % self.sid,
                         {"path": os.path.abspath(path), "temporary": temporary})["value"]

    def go(self, url):
        return self._req("POST", "/session/%s/url" % self.sid, {"url": url})

    def quit(self):
        if self.sid:
            try:
                self._req("DELETE", "/session/%s" % self.sid)
            except Exception:
                pass

# Runs in chrome scope. Lock state can only be asked honestly from here.
PREF_DUMP = """
const names = arguments[0];
const out = {};
for (const n of names) {
  let v = null, type = Services.prefs.getPrefType(n);
  try {
    if (type === Services.prefs.PREF_BOOL) v = Services.prefs.getBoolPref(n);
    else if (type === Services.prefs.PREF_INT) v = Services.prefs.getIntPref(n);
    else if (type === Services.prefs.PREF_STRING) v = Services.prefs.getStringPref(n);
  } catch (e) { v = "<unreadable>"; }
  out[n] = {
    value: v,
    locked: Services.prefs.prefIsLocked(n),
    userSet: Services.prefs.prefHasUserValue(n),
    exists: type !== Services.prefs.PREF_INVALID,
  };
}
out["<policies>"] = {
  policiesActive: !!(Services.policies && Services.policies.status),
  status: Services.policies ? Services.policies.status : null,
};
return out;
"""

# Content scope. Only what a page can actually see.
FP_DUMP = """
const n = navigator, s = screen;
function safe(f, d) { try { return f(); } catch (e) { return d; } }
return {
  userAgent: n.userAgent, platform: n.platform, language: n.language,
  languages: safe(() => n.languages.join(","), null),
  hardwareConcurrency: n.hardwareConcurrency,
  deviceMemory: safe(() => n.deviceMemory, null),
  maxTouchPoints: n.maxTouchPoints, doNotTrack: n.doNotTrack,
  screen: [s.width, s.height, s.availWidth, s.availHeight, s.colorDepth, s.pixelDepth],
  innerSize: [window.innerWidth, window.innerHeight],
  devicePixelRatio: window.devicePixelRatio,
  timezone: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone, null),
  tzOffset: new Date().getTimezoneOffset(),
  webdriver: n.webdriver,
  plugins: safe(() => Array.from(n.plugins).map(p => p.name), []),
  mimeTypes: safe(() => Array.from(n.mimeTypes).map(m => m.type), []),
  webrtc: typeof RTCPeerConnection,
  canvas: safe(() => {
    const c = document.createElement("canvas"); c.width = 60; c.height = 20;
    const x = c.getContext("2d"); x.textBaseline = "top"; x.font = "14px sans-serif";
    x.fillText("nmp", 2, 2); return c.toDataURL().slice(-48);
  }, null),
  webglVendor: safe(() => {
    const g = document.createElement("canvas").getContext("webgl");
    const d = g.getExtension("WEBGL_debug_renderer_info");
    return [g.getParameter(d.UNMASKED_VENDOR_WEBGL), g.getParameter(d.UNMASKED_RENDERER_WEBGL)];
  }, null),
  audioCtxRate: safe(() => new (window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,1,44100).sampleRate, null),
  fonts: safe(() => {
    const probe = ["monospace","serif","sans-serif","Arial","Times New Roman","Courier New",
                   "DejaVu Sans","Liberation Serif","Noto Sans CJK KR","Malgun Gothic"];
    const span = document.createElement("span"); span.textContent = "mmmMMMwww";
    span.style.fontSize = "72px"; document.body.appendChild(span);
    const out = {};
    for (const f of probe) { span.style.fontFamily = f; out[f] = span.offsetWidth; }
    span.remove(); return out;
  }, null),
};
"""

# The exact path an ad blocker's CNAME uncloaking takes, called directly rather
# than through an extension. The return value does not matter: the namespace
# counters deliver the verdict. This only has to provoke.
DNS_PROBE = """
const done = arguments[arguments.length - 1];
const hosts = ["example.com", "cname-probe.nmp.invalid", "mozilla.org"];
const log = [];
let left = hosts.length;
const finish = () => { if (--left <= 0) done(log); };
for (const h of hosts) {
  try {
    Services.dns.asyncResolve(h, 0, 0, null, {
      onLookupComplete(req, rec, status) {
        let addr = null;
        try { addr = rec.getNextAddrAsString(); } catch (e) {}
        log.push({host: h, status: status, addr: addr});
        finish();
      },
    }, null, {});
  } catch (e) { log.push({host: h, threw: String(e)}); finish(); }
}
setTimeout(() => done(log), 8000);
"""

# The base leaves WebRTC on and tightens ICE instead (relay_only,
# proxy_only_if_behind_proxy). Whether that actually holds the proxy is answered
# by making it gather candidates: the attempt itself is counted, so a verdict
# stands even if nothing reaches the outside.
WEBRTC_PROBE = """
const done = arguments[arguments.length - 1];
const out = {candidates: [], errors: [], state: null};
try {
  const pc = new RTCPeerConnection({
    iceServers: [{urls: "stun:stun.l.google.com:19302"},
                 {urls: "turn:turn.example.invalid:3478", username: "u", credential: "p"}],
  });
  pc.onicecandidate = (e) => {
    if (e.candidate) out.candidates.push(e.candidate.candidate);
    else { out.state = "complete"; done(out); }
  };
  pc.createDataChannel("nmp");
  pc.createOffer().then((o) => pc.setLocalDescription(o))
    .catch((e) => { out.errors.push(String(e)); });
} catch (e) {
  out.errors.push(String(e));
  done(out);
}
setTimeout(() => { out.state = "timed out"; done(out); }, 12000);
"""

WATCHED = [
    "network.proxy.type", "network.proxy.socks", "network.proxy.socks_port",
    "network.proxy.socks_version",
    # Both: Firefox 128 split them, and either one off lets names out.
    "network.proxy.socks_remote_dns", "network.proxy.socks5_remote_dns",
    # The HTTP proxy the I2P route uses, and which a SOCKS route must leave empty.
    "network.proxy.http", "network.proxy.http_port",
    "network.proxy.ssl", "network.proxy.ssl_port",
    "network.proxy.allow_hijacking_localhost", "network.proxy.no_proxies_on",
    "network.proxy.failover_direct", "network.proxy.allow_bypass",
    "network.http.http3.enable", "media.peerconnection.enabled",
    "network.trr.mode", "network.trr.uri", "network.dns.disabled",
    "privacy.resistFingerprinting", "app.update.auto", "extensions.update.enabled",
    "browser.safebrowsing.malware.enabled", "security.OCSP.enabled",
    "network.captive-portal-service.enabled", "network.connectivity-service.enabled",
    # What the launcher's lock file says about itself: that it ran to the end,
    # which profile it decided it was in, and the route the window is marked
    # with. Absent on a browser without it.
    "bbiwy.lock.complete", "bbiwy.lock.profile",
    "bbiwy.path.daily", "bbiwy.path.hardened", "bbiwy.path.tor",
    "bbiwy.path.i2p", "bbiwy.path.session",
]

def wait_port(port, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False

_grants = {}

def driver_grants_system_access(geckodriver):
    """Whether this geckodriver has --allow-system-access (0.36 and later).

    Asked of the binary itself rather than read off its version number: the
    flag is what matters, and --help lists it.
    """
    if geckodriver not in _grants:
        try:
            r = subprocess.run([geckodriver, "--help"], capture_output=True, text=True, timeout=30)
            _grants[geckodriver] = "--allow-system-access" in (r.stdout + r.stderr)
        except (OSError, subprocess.SubprocessError):
            _grants[geckodriver] = False
    return _grants[geckodriver]

def start_geckodriver(geckodriver, port, env=None):
    """Starts geckodriver on `port`. Returns the process, and a WD for it that
    asks for chrome scope the way this geckodriver wants to be asked."""
    grants = driver_grants_system_access(geckodriver)
    cmd = [geckodriver, "--port", str(port), "--log", "error"]
    if grants:
        cmd.append("--allow-system-access")
    gd = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    return gd, WD(port, driver_grants=grants)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--geckodriver", required=True)
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--addon", help="extension to install temporarily (xpi or directory)")
    ap.add_argument("--url", default="about:blank")
    ap.add_argument("--out", help="where to write the result JSON")
    ap.add_argument("--hold", type=float, default=6.0, help="seconds to linger after measuring")
    ap.add_argument("--webrtc-probe", action="store_true",
                    help="gather WebRTC candidates, to test whether ICE holds the proxy")
    ap.add_argument("--dns-probe", action="store_true",
                    help="call nsIDNSService directly from chrome scope to provoke a leak")
    ap.add_argument("--headless", action="store_true",
                    help="run the browser without a window, so no display is needed")
    a = ap.parse_args()

    gd, wd = start_geckodriver(a.geckodriver, a.port)
    out = {"prefs": None, "fingerprint": None, "addon": None, "errors": []}
    try:
        if not wait_port(a.port):
            sys.exit("geckodriver did not start")
        wd.start(a.binary, a.profile, ["--headless"] if a.headless else None)

        wd.ctx("chrome")
        out["prefs"] = wd.script(PREF_DUMP, [WATCHED])

        if a.addon:
            try:
                wd.ctx("content")
                out["addon"] = wd.install(a.addon, temporary=True)
            except Exception as e:
                out["errors"].append("extension install failed: %s" % e)

        wd.ctx("content")
        wd.go(a.url)
        time.sleep(1.0)
        try:
            out["fingerprint"] = wd.script(FP_DUMP)
        except Exception as e:
            out["errors"].append("fingerprint dump failed: %s" % e)

        if a.webrtc_probe:
            try:
                wd.ctx("content")
                wd._req("POST", "/session/%s/timeouts" % wd.sid, {"script timeout": 30000})
                wd.go("data:text/html,<title>rtc</title>")  # RTC cannot be constructed on about: pages
                out["webrtc"] = wd.script_async(WEBRTC_PROBE)
            except Exception as e:
                out["errors"].append("WebRTC probe failed: %s" % e)

        if a.dns_probe:
            try:
                wd.ctx("chrome")
                self_to = {"script timeout": 30000}
                wd._req("POST", "/session/%s/timeouts" % wd.sid, self_to)
                out["dns_probe"] = wd.script_async(DNS_PROBE)
            except Exception as e:
                out["errors"].append("DNS probe failed: %s" % e)

        time.sleep(a.hold)   # give the extension time to resolve
    finally:
        wd.quit()
        gd.terminate()
        try:
            gd.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gd.kill()

    text = json.dumps(out, indent=2, ensure_ascii=False, sort_keys=True)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
        print("wrote: %s" % a.out)
    p = out["prefs"] or {}
    print("%-46s %-14s %-6s %s" % ("pref", "value", "locked", "user-set"))
    for k in WATCHED:
        d = p.get(k)
        if not d:
            continue
        print("%-46s %-14s %-6s %s" % (k, str(d["value"])[:14],
                                       "yes" if d["locked"] else "no",
                                       "yes" if d["userSet"] else "no"))
    if "<policies>" in p:
        print("\npolicies active: %s" % p["<policies>"])
    if out.get("webrtc") is not None:
        w = out["webrtc"]
        print("\nWebRTC candidates: %d · state %s" % (len(w.get("candidates", [])), w.get("state")))
        for c in w.get("candidates", [])[:8]:
            print("  %s" % c)
        for e in w.get("errors", []):
            print("  error: %s" % e)
    if out.get("dns_probe") is not None:
        print("\ndirect nsIDNSService call: %s" % json.dumps(out["dns_probe"], ensure_ascii=False))
    for e in out["errors"]:
        print("error: %s" % e)


if __name__ == "__main__":
    main()
