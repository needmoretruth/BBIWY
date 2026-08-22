#!/usr/bin/env python3
"""fpsplit — 오너가 정한 4:1 지문 분리가 실제로 일어나는지 잰다.

규칙(오너 2026-08-22): 프라이버시 프로필 4개는 지문을 통일하고, 데일리 프로필
1개만 별도 지문을 갖는다.

여기서 재는 것은 두 가지다.
  통일  : 프라이버시 4개 사이의 지문 차이가 0인가.
  분리  : 데일리가 그 넷과 실제로 다른가. (다르지 않으면 데일리를 만든 의미가 없다)

분기는 환경변수가 아니라 **실행 중인 프로필의 실제 경로**로 한다. 환경변수는 사용자가
위조할 수 있어서 잠금의 뜻이 사라진다. 실측 11 참조.
"""
import argparse, importlib.util, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drive)

sys.path.insert(0, os.path.join(HERE, "..", "leakcheck"))
import fpdiff

PROFILES = ["daily", "hardened", "tor", "i2p", "session"]
PRIVACY = ["hardened", "tor", "i2p", "session"]

# 실행 중인 프로필 경로의 마지막 조각으로 부류를 정한다.
MOZILLA_CFG = r'''// NMP autoconfig — 첫 줄은 반드시 주석
try {
  var klass = "privacy";
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    if (/(^|[\/\-])daily([\-\.]|$)/.test(String(d.leafName))) klass = "daily";
    lockPref("nmp.profile.path", String(d.path));
  } catch (e) {
    // 경로를 못 읽으면 가장 안전한 쪽으로 떨어진다 — 프라이버시로 잠근다.
    lockPref("nmp.profile.path", "«실패»");
  }
  lockPref("nmp.profile.class", klass);

  if (klass === "daily") {
    unlockPref("privacy.resistFingerprinting");
    defaultPref("privacy.resistFingerprinting", false);
    lockPref("privacy.fingerprintingProtection", true);
    unlockPref("privacy.resistFingerprinting.letterboxing");
    defaultPref("privacy.resistFingerprinting.letterboxing", false);
  } else {
    lockPref("privacy.resistFingerprinting", true);
    lockPref("privacy.fingerprintingProtection", false);
  }
} catch (e) {}
'''

LOCAL_SETTINGS = ('pref("general.config.filename", "mozilla.cfg");\n'
                  'pref("general.config.obscure_value", 0);\n'
                  'pref("general.config.sandbox_enabled", false);\n')

WATCH = ["privacy.resistFingerprinting", "privacy.fingerprintingProtection",
         "nmp.profile.class", "nmp.profile.path"]


def install_autoconfig(browser_dir):
    made = []
    cfg = os.path.join(browser_dir, "mozilla.cfg")
    ls_dir = os.path.join(browser_dir, "defaults", "pref")
    os.makedirs(ls_dir, exist_ok=True)
    ls = os.path.join(ls_dir, "local-settings.js")
    open(cfg, "w").write(MOZILLA_CFG)
    open(ls, "w").write(LOCAL_SETTINGS)
    return [cfg, ls]


def measure(binary, gecko, port, profdir):
    gd = subprocess.Popen([gecko, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not drive.wait_port(port, 30):
            return {"«오류»": "geckodriver 가 뜨지 않았습니다"}
        wd = drive.WD(port)
        wd.start(binary, profdir)
        try:
            wd.ctx("chrome")
            prefs = wd.script(drive.PREF_DUMP, [WATCH])
            wd.ctx("content")
            wd.go("data:text/html,<title>fp</title>")
            time.sleep(0.5)
            fp = wd.script(drive.FP_DUMP)
            return {"prefs": prefs, "fingerprint": fp}
        finally:
            wd.quit()
    finally:
        gd.terminate()
        try: gd.wait(timeout=10)
        except Exception: gd.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--geckodriver", required=True)
    ap.add_argument("--port", type=int, default=4470)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    browser_dir = os.path.dirname(os.path.abspath(a.binary))
    made = install_autoconfig(browser_dir)
    root = tempfile.mkdtemp(prefix="nmp-fpsplit-")
    results = {}
    try:
        for i, name in enumerate(PROFILES):
            pdir = os.path.join(root, "nmp-" + name)
            os.makedirs(pdir, exist_ok=True)
            print("── %s" % name, flush=True)
            results[name] = measure(a.binary, a.geckodriver, a.port + i, pdir)
            time.sleep(1)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        for p in made:
            try: os.remove(p)
            except OSError: pass

    json.dump(results, open(a.out, "w"), ensure_ascii=False, indent=2)

    # ── 판정 ────────────────────────────────────────────────
    flat = {n: fpdiff.flat(results[n].get("fingerprint")) for n in results}
    keys = sorted(set().union(*[set(v) for v in flat.values()]))

    print("\n=== 잠금 상태 ===")
    for n in PROFILES:
        p = results[n].get("prefs", {})
        rfp = p.get("privacy.resistFingerprinting", {})
        fpp = p.get("privacy.fingerprintingProtection", {})
        print("  %-9s class=%-8s RFP=%-5s[%s]  FPP=%-5s[%s]" % (
            n, p.get("nmp.profile.class", {}).get("value"),
            rfp.get("value"), "잠김" if rfp.get("locked") else "열림",
            fpp.get("value"), "잠김" if fpp.get("locked") else "열림"))

    print("\n=== 통일: 프라이버시 4개 사이의 차이 ===")
    unified_break = []
    for k in keys:
        if k.split(".")[0] in fpdiff.NOISY:
            continue
        vals = {flat[n].get(k, "«없음»") for n in PRIVACY}
        if len(vals) > 1:
            unified_break.append((k, {n: flat[n].get(k) for n in PRIVACY}))
    if not unified_break:
        print("  차이 0 — 프라이버시 4개는 구별되지 않습니다.")
    else:
        for k, v in unified_break:
            print("  ⛔ %s → %s" % (k, v))

    print("\n=== 분리: 데일리가 프라이버시와 다른 항목 ===")
    sep = []
    for k in keys:
        if k.split(".")[0] in fpdiff.NOISY:
            continue
        base = flat["hardened"].get(k, "«없음»")
        d = flat["daily"].get(k, "«없음»")
        if base != d:
            sep.append((k, base, d))
    if not sep:
        print("  ⛔ 차이 0 — 데일리를 따로 만든 의미가 없습니다.")
    else:
        for k, b, d in sep:
            print("  %-28s 프라이버시=%s  데일리=%s" % (k, str(b)[:34], str(d)[:34]))

    print("\n=== 판정 ===")
    print("  통일(프라이버시 4개 차이 0): %s" % ("통과" if not unified_break else "실패"))
    print("  분리(데일리가 실제로 다름): %s" % ("통과" if sep else "실패"))


if __name__ == "__main__":
    main()
