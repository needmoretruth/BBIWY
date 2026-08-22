#!/usr/bin/env python3
"""dspdiff — run the same profile under X11 and under Wayland, and compare.

Can Wayland be supported without splitting the fingerprint?

Upstream disabled Wayland not because of a known leak but because, in the words
"We don't really have any fingerprinting insight into the difference between wayland
and non-wayland". That is an absence of measurement, so: measure it.

If the difference is zero, Wayland need be neither required nor forbidden.
If it is not, this says exactly which items are responsible.
"""
import argparse, importlib.util, json, os, shutil, signal, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(HERE_F := __file__))
_s = importlib.util.spec_from_file_location("drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_s); _s.loader.exec_module(drive)
sys.path.insert(0, os.path.join(HERE, "..", "leakcheck"))
import fpdiff

W, H = 1400, 900

CFG = '''// identical locks for both runs
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
    prof = tempfile.mkdtemp(prefix="bbiwy-%s-" % label)
    e = dict(os.environ); e.update(env)
    for k in ("DISPLAY", "WAYLAND_DISPLAY"):
        if k in env and env[k] is None:
            e.pop(k, None)
    e = {k: v for k, v in e.items() if v is not None}
    gd = subprocess.Popen([gecko, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=e)
    try:
        if not drive.wait_port(port, 30):
            return {"<error>": "geckodriver did not start"}
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
        # ── X11 (Xvfb is started outside, by xvfb-run)
        print("── X11", flush=True)
        res["x11"] = measure(a.binary, a.geckodriver, a.port,
                             {"MOZ_ENABLE_WAYLAND": "0", "WAYLAND_DISPLAY": None}, "x11")

        # ── Wayland (headless weston)
        print("── Wayland (headless weston)", flush=True)
        rt = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
        os.makedirs(rt, exist_ok=True); os.chmod(rt, 0o700)
        wl = subprocess.Popen(
            ["weston", "--backend=headless", "--width=%d" % W, "--height=%d" % H,
             "--socket=wayland-bbiwy", "--idle-time=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            env=dict(os.environ, XDG_RUNTIME_DIR=rt))
        try:
            sock = os.path.join(rt, "wayland-bbiwy")
            for _ in range(120):
                if os.path.exists(sock): break
                time.sleep(0.25)
            if not os.path.exists(sock):
                res["wayland"] = {"<error>": "weston socket never appeared: %s" % sock}
            else:
                res["wayland"] = measure(a.binary, a.geckodriver, a.port + 1,
                                         {"MOZ_ENABLE_WAYLAND": "1",
                                          "WAYLAND_DISPLAY": "wayland-bbiwy",
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
    if any("<error>" in v for v in res.values()):
        for k, v in res.items():
            if "<error>" in v: print("  %s: %s" % (k, v["<error>"]))
        return
    flat = {k: fpdiff.flat(v.get("fingerprint")) for k, v in res.items()}
    keys = sorted(set(flat["x11"]) | set(flat["wayland"]))
    diff = [(k, flat["x11"].get(k, "<absent>"), flat["wayland"].get(k, "<absent>"))
            for k in keys if k.split(".")[0] not in fpdiff.NOISY
            and flat["x11"].get(k, "<absent>") != flat["wayland"].get(k, "<absent>")]
    print("\n=== X11 vs Wayland — fingerprint difference ===")
    if not diff:
        print("  zero differences — a page cannot tell the display servers apart.")
    for k, x, w in diff:
        print("  %-22s X11=%-30s wayland=%s" % (k, str(x)[:30], str(w)[:34]))
    print("\n%d of %d items differ" % (len(diff), len(keys)))

if __name__ == "__main__":
    main()
