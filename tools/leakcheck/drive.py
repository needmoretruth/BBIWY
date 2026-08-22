#!/usr/bin/env python3
"""drive — geckodriver로 브라우저를 몰아 계측하는 하네스.

세 가지를 잰다. 셋 다 눈으로는 안 보이는 것들이다.

  잠금  : pref가 실제로 잠겼는가. Services.prefs.prefIsLocked 를 chrome 권한으로 물어본다.
          user.js / policies.json / autoconfig 중 무엇이 먹는지가 여기서 갈린다.
  누수  : 확장이 browser.dns.resolve 를 부르면 프록시를 우회하는가.
          판정은 이 프로그램이 아니라 격리망 계수기가 한다 — 여기서는 유발만 한다.
  지문  : content 권한에서 보이는 표면을 JSON으로 뽑는다. 프로필 간·판올림 간 diff 용.

표준 라이브러리만 쓴다. selenium을 넣으면 그 버전이 또 하나의 변수가 된다.
"""
import argparse, json, os, socket, subprocess, sys, time, urllib.request

class WD:
    def __init__(self, port):
        self.base = "http://127.0.0.1:%d" % port
        self.sid = None

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
        caps = {
            "capabilities": {
                "alwaysMatch": {
                    "moz:firefoxOptions": {
                        "binary": binary,
                        "args": ["--profile", profile, "--no-remote", "-remote-allow-system-access"] + (extra_args or []),
                        "prefs": {"marionette.enabled": True},
                    },
                    "acceptInsecureCerts": True,
                }
            }
        }
        self.sid = self._req("POST", "/session", caps)["value"]["sessionId"]
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

# chrome 권한에서 도는 조각. 잠금 여부는 이 경로로만 정직하게 물어볼 수 있다.
PREF_DUMP = """
const names = arguments[0];
const out = {};
for (const n of names) {
  let v = null, type = Services.prefs.getPrefType(n);
  try {
    if (type === Services.prefs.PREF_BOOL) v = Services.prefs.getBoolPref(n);
    else if (type === Services.prefs.PREF_INT) v = Services.prefs.getIntPref(n);
    else if (type === Services.prefs.PREF_STRING) v = Services.prefs.getStringPref(n);
  } catch (e) { v = "«읽기실패»"; }
  out[n] = {
    value: v,
    locked: Services.prefs.prefIsLocked(n),
    userSet: Services.prefs.prefHasUserValue(n),
    exists: type !== Services.prefs.PREF_INVALID,
  };
}
out["«정책»"] = {
  policiesActive: !!(Services.policies && Services.policies.status),
  status: Services.policies ? Services.policies.status : null,
};
return out;
"""

# content 권한. 페이지가 실제로 볼 수 있는 것만 담는다.
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

# uBO의 CNAME 언클로킹이 내려가는 바로 그 경로다. 확장을 거치지 않고 같은 것을 부른다.
# 결과값은 중요하지 않다 — 판정은 격리망 계수기가 한다. 여기서는 유발만 하면 된다.
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

# Mullvad Browser 는 WebRTC 를 켠 채 ICE 를 조여 둔다(relay_only · proxy_only_if_behind_proxy).
# 그 조임이 실제로 프록시를 지키는지는 후보 수집을 시켜 보면 안다. 나가려는 시도 자체가
# 격리망 계수기에 잡히므로, 밖에 닿지 않아도 판정이 선다.
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
    else { out.state = "완료"; done(out); }
  };
  pc.createDataChannel("nmp");
  pc.createOffer().then((o) => pc.setLocalDescription(o))
    .catch((e) => { out.errors.push(String(e)); });
} catch (e) {
  out.errors.push(String(e));
  done(out);
}
setTimeout(() => { out.state = "시간초과"; done(out); }, 12000);
"""

WATCHED = [
    "network.proxy.type", "network.proxy.socks", "network.proxy.socks_port",
    "network.proxy.socks_remote_dns", "network.proxy.allow_hijacking_localhost",
    "network.proxy.failover_direct", "media.peerconnection.enabled",
    "network.trr.mode", "network.trr.uri", "network.dns.disabled",
    "privacy.resistFingerprinting", "app.update.auto", "extensions.update.enabled",
    "browser.safebrowsing.malware.enabled", "security.OCSP.enabled",
    "network.captive-portal-service.enabled", "network.connectivity-service.enabled",
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--geckodriver", required=True)
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--addon", help="임시 설치할 확장 (xpi 또는 폴더)")
    ap.add_argument("--url", default="about:blank")
    ap.add_argument("--out", help="결과 JSON 경로")
    ap.add_argument("--hold", type=float, default=6.0, help="측정 후 머무는 시간(초)")
    ap.add_argument("--webrtc-probe", action="store_true",
                    help="WebRTC 후보 수집을 시켜 ICE 가 프록시를 지키는지 재는 유발을 한다")
    ap.add_argument("--dns-probe", action="store_true",
                    help="chrome 권한에서 nsIDNSService를 직접 불러 누수를 유발한다")
    a = ap.parse_args()

    gd = subprocess.Popen([a.geckodriver, "--port", str(a.port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = {"prefs": None, "fingerprint": None, "addon": None, "errors": []}
    wd = WD(a.port)
    try:
        if not wait_port(a.port):
            sys.exit("geckodriver 가 뜨지 않았습니다")
        wd.start(a.binary, a.profile)

        wd.ctx("chrome")
        out["prefs"] = wd.script(PREF_DUMP, [WATCHED])

        if a.addon:
            try:
                wd.ctx("content")
                out["addon"] = wd.install(a.addon, temporary=True)
            except Exception as e:
                out["errors"].append("확장 설치 실패: %s" % e)

        wd.ctx("content")
        wd.go(a.url)
        time.sleep(1.0)
        try:
            out["fingerprint"] = wd.script(FP_DUMP)
        except Exception as e:
            out["errors"].append("지문 수집 실패: %s" % e)

        if a.webrtc_probe:
            try:
                wd.ctx("content")
                wd._req("POST", "/session/%s/timeouts" % wd.sid, {"script timeout": 30000})
                wd.go("data:text/html,<title>rtc</title>")  # about: 페이지에서는 RTC 를 못 만든다
                out["webrtc"] = wd.script_async(WEBRTC_PROBE)
            except Exception as e:
                out["errors"].append("WebRTC 유발 실패: %s" % e)

        if a.dns_probe:
            try:
                wd.ctx("chrome")
                self_to = {"script timeout": 30000}
                wd._req("POST", "/session/%s/timeouts" % wd.sid, self_to)
                out["dns_probe"] = wd.script_async(DNS_PROBE)
            except Exception as e:
                out["errors"].append("DNS 유발 실패: %s" % e)

        time.sleep(a.hold)   # 확장이 이름을 풀 시간을 준다
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
        print("기록: %s" % a.out)
    p = out["prefs"] or {}
    print("%-46s %-14s %-6s %s" % ("설정", "값", "잠김", "사용자값"))
    for k in WATCHED:
        d = p.get(k)
        if not d:
            continue
        print("%-46s %-14s %-6s %s" % (k, str(d["value"])[:14],
                                       "예" if d["locked"] else "아니오",
                                       "예" if d["userSet"] else "아니오"))
    if "«정책»" in p:
        print("\n정책 활성: %s" % p["«정책»"])
    if out.get("webrtc") is not None:
        w = out["webrtc"]
        print("\nWebRTC 후보 %d개 · 상태 %s" % (len(w.get("candidates", [])), w.get("state")))
        for c in w.get("candidates", [])[:8]:
            print("  %s" % c)
        for e in w.get("errors", []):
            print("  오류: %s" % e)
    if out.get("dns_probe") is not None:
        print("\nnsIDNSService 직접 호출 결과: %s" % json.dumps(out["dns_probe"], ensure_ascii=False))
    for e in out["errors"]:
        print("오류: %s" % e)


if __name__ == "__main__":
    main()
