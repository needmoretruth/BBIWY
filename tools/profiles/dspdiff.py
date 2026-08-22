#!/usr/bin/env python3
"""dspdiff — 같은 프로필을 X11 과 웨이랜드에서 각각 띄워 지문을 견준다.

오너 질문(2026-08-22): 웨이랜드를 쓰면서도 지문이 통일되게 할 수 없나.

Tor 가 웨이랜드를 끈 이유는 「샌다」가 아니라 「안 재 봤다」였다. 결정 코멘트 원문이
"We don't really have any fingerprinting insight into the difference between wayland
and non-wayland" 이다. 그래서 잰다.

차이가 0 이면 웨이랜드를 요구하지도 금지하지도 않고 둘 다 허용할 수 있다.
0 이 아니면 어느 항목인지 정확히 알게 된다.
"""
import argparse, importlib.util, json, os, shutil, signal, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(HERE_F := __file__))
_s = importlib.util.spec_from_file_location("drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_s); _s.loader.exec_module(drive)
sys.path.insert(0, os.path.join(HERE, "..", "leakcheck"))
import fpdiff

W, H = 1400, 900

CFG = '''// NMP — 두 실행에 완전히 같은 잠금을 건다
try {
  lockPref("privacy.resistFingerprinting", true);
  lockPref("privacy.resistFingerprinting.letterboxing", true);
  lockPref("privacy.fingerprintingProtection", false);
} catch (e) {}
'''
LS = ('pref("general.config.filename", "mozilla.cfg");\n'
      'pref("general.config.obscure_value", 0);\n'
      'pref("general.config.sandbox_enabled", false);\n')

EXTRA = """
return {
  wayland_hint: (function(){ try { return window.matchMedia('(-moz-platform: linux)').matches; } catch(e){ return null; } })(),
  screenXY: [window.screenX, window.screenY],
  outer: [window.outerWidth, window.outerHeight],
  colorGamut: (function(){ try { for (const g of ['srgb','p3','rec2020']) if (matchMedia('(color-gamut: '+g+')').matches) return g; } catch(e){} return null; })(),
  refresh: (function(){ try { return matchMedia('(update: fast)').matches ? 'fast' : (matchMedia('(update: slow)').matches ? 'slow' : 'none'); } catch(e){ return null; } })(),
  prefersReducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
  pointerFine: matchMedia('(pointer: fine)').matches,
  anyHover: matchMedia('(any-hover: hover)').matches,
};
"""

def measure(binary, gecko, port, env, label):
    prof = tempfile.mkdtemp(prefix="nmp-%s-" % label)
    e = dict(os.environ); e.update(env)
    for k in ("DISPLAY", "WAYLAND_DISPLAY"):
        if k in env and env[k] is None:
            e.pop(k, None)
    e = {k: v for k, v in e.items() if v is not None}
    gd = subprocess.Popen([gecko, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=e)
    try:
        if not drive.wait_port(port, 30):
            return {"«오류»": "geckodriver 미기동"}
        wd = drive.WD(port); wd.start(binary, prof)
        try:
            wd._req("POST", "/session/%s/window/rect" % wd.sid,
                    {"width": W, "height": H, "x": 0, "y": 0})
            time.sleep(1.5)
            wd.ctx("content"); wd.go("data:text/html,<title>d</title>")
            time.sleep(0.8)
            fp = wd.script(drive.FP_DUMP)
            fp.update(wd.script(EXTRA))
            return {"fingerprint": fp}
        finally:
            wd.quit()
    finally:
        gd.terminate()
        try: gd.wait(timeout=10)
        except Exception: gd.kill()
        shutil.rmtree(prof, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True); ap.add_argument("--geckodriver", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--port", type=int, default=4500)
    a = ap.parse_args()
    bdir = os.path.dirname(os.path.abspath(a.binary))
    cfg = os.path.join(bdir, "mozilla.cfg")
    lsd = os.path.join(bdir, "defaults", "pref"); os.makedirs(lsd, exist_ok=True)
    ls = os.path.join(lsd, "local-settings.js")
    open(cfg, "w").write(CFG); open(ls, "w").write(LS)

    res = {}
    try:
        # ── X11 (Xvfb 는 바깥에서 xvfb-run 이 띄운다)
        print("── X11", flush=True)
        res["x11"] = measure(a.binary, a.geckodriver, a.port,
                             {"MOZ_ENABLE_WAYLAND": "0", "WAYLAND_DISPLAY": None}, "x11")

        # ── 웨이랜드 (weston 헤드리스)
        print("── 웨이랜드 (weston 헤드리스)", flush=True)
        rt = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
        os.makedirs(rt, exist_ok=True); os.chmod(rt, 0o700)
        wl = subprocess.Popen(
            ["weston", "--backend=headless", "--width=%d" % W, "--height=%d" % H,
             "--socket=wayland-nmp", "--idle-time=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            env=dict(os.environ, XDG_RUNTIME_DIR=rt))
        try:
            sock = os.path.join(rt, "wayland-nmp")
            for _ in range(120):
                if os.path.exists(sock): break
                time.sleep(0.25)
            if not os.path.exists(sock):
                res["wayland"] = {"«오류»": "weston 소켓이 안 생겼습니다: %s" % sock}
            else:
                res["wayland"] = measure(a.binary, a.geckodriver, a.port + 1,
                                         {"MOZ_ENABLE_WAYLAND": "1",
                                          "WAYLAND_DISPLAY": "wayland-nmp",
                                          "XDG_RUNTIME_DIR": rt,
                                          "DISPLAY": None}, "wl")
        finally:
            wl.send_signal(signal.SIGTERM)
            try: wl.wait(timeout=10)
            except Exception: wl.kill()
    finally:
        for f in (cfg, ls):
            try: os.remove(f)
            except OSError: pass

    json.dump(res, open(a.out, "w"), ensure_ascii=False, indent=2)
    if any("«오류»" in v for v in res.values()):
        for k, v in res.items():
            if "«오류»" in v: print("  %s: %s" % (k, v["«오류»"]))
        return
    flat = {k: fpdiff.flat(v.get("fingerprint")) for k, v in res.items()}
    keys = sorted(set(flat["x11"]) | set(flat["wayland"]))
    diff = [(k, flat["x11"].get(k, "«없음»"), flat["wayland"].get(k, "«없음»"))
            for k in keys if k.split(".")[0] not in fpdiff.NOISY
            and flat["x11"].get(k, "«없음»") != flat["wayland"].get(k, "«없음»")]
    print("\n=== X11 대 웨이랜드 — 지문 차이 ===")
    if not diff:
        print("  차이 0 — 페이지는 두 표시서버를 구별하지 못합니다.")
    for k, x, w in diff:
        print("  %-22s X11=%-30s 웨이랜드=%s" % (k, str(x)[:30], str(w)[:34]))
    print("\n항목 %d개 중 %d개 다름" % (len(keys), len(diff)))

if __name__ == "__main__":
    main()
