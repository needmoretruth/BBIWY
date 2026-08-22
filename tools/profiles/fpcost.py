#!/usr/bin/env python3
"""fpcost — 「데일리를 쓸 만하게 만드는 것」이 지문을 얼마나 깨는가.

오너 질문(2026-08-22): 5개 다 뮬바드 기반인데 데일리만 지문을 다르게 할 이유가 있나.

그 답은 「무엇을 풀어 주느냐에 달렸다」이고, 항목마다 값이 다르다. 어떤 완화는
지문에 전혀 안 보이고(공짜), 어떤 완화는 곧바로 지문 차이가 된다(대가). 그 선을
추측이 아니라 실제 값으로 긋는다.

기준선은 뮬바드 기본값(RFP 잠금 + 레터박싱)이고, 나머지를 기준선과 견준다.
"""
import argparse, importlib.util, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drive)
sys.path.insert(0, os.path.join(HERE, "..", "leakcheck"))
import fpdiff

# 프로필 폴더 이름 → autoconfig 안에서 고를 설정 이름
CONFIGS = ["base", "nolb", "persist", "norfp"]
LABEL = {
    "base":    "기준선 — 뮬바드 기본값 (RFP 잠금 + 레터박싱)",
    "nolb":    "레터박싱만 끔 (RFP 는 그대로 잠김)",
    "persist": "로그인·기록 유지 (RFP·레터박싱 그대로)",
    "norfp":   "RFP 끔 + FPP 켬 (앞서 데일리로 재 본 것)",
}

MOZILLA_CFG = r'''// NMP autoconfig — 첫 줄은 반드시 주석
try {
  var name = "base";
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    var m = String(d.leafName).match(/nmp-([a-z]+)/);
    if (m) name = m[1];
  } catch (e) {}
  lockPref("nmp.config", name);

  if (name === "norfp") {
    unlockPref("privacy.resistFingerprinting");
    defaultPref("privacy.resistFingerprinting", false);
    lockPref("privacy.fingerprintingProtection", true);
  } else {
    lockPref("privacy.resistFingerprinting", true);
    lockPref("privacy.fingerprintingProtection", false);
  }

  if (name === "nolb") {
    lockPref("privacy.resistFingerprinting.letterboxing", false);
  } else if (name !== "norfp") {
    lockPref("privacy.resistFingerprinting.letterboxing", true);
  }

  if (name === "persist") {
    // 「쓸 만함」의 대부분은 여기다 — 로그인이 남고, 기록이 남고, 나갈 때 안 지운다
    lockPref("browser.privatebrowsing.autostart", false);
    lockPref("privacy.sanitize.sanitizeOnShutdown", false);
    lockPref("signon.rememberSignons", true);
    lockPref("places.history.enabled", true);
    lockPref("browser.formfill.enable", true);
  }
} catch (e) {}
'''

LOCAL_SETTINGS = ('pref("general.config.filename", "mozilla.cfg");\n'
                  'pref("general.config.obscure_value", 0);\n'
                  'pref("general.config.sandbox_enabled", false);\n')

WATCH = ["nmp.config", "privacy.resistFingerprinting",
         "privacy.resistFingerprinting.letterboxing",
         "privacy.fingerprintingProtection",
         "browser.privatebrowsing.autostart", "signon.rememberSignons"]


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
            time.sleep(0.6)
            return {"prefs": prefs, "fingerprint": wd.script(drive.FP_DUMP)}
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
    ap.add_argument("--port", type=int, default=4480)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    bdir = os.path.dirname(os.path.abspath(a.binary))
    cfg = os.path.join(bdir, "mozilla.cfg")
    lsd = os.path.join(bdir, "defaults", "pref"); os.makedirs(lsd, exist_ok=True)
    ls = os.path.join(lsd, "local-settings.js")
    open(cfg, "w").write(MOZILLA_CFG); open(ls, "w").write(LOCAL_SETTINGS)

    root = tempfile.mkdtemp(prefix="nmp-fpcost-")
    res = {}
    try:
        for i, name in enumerate(CONFIGS):
            p = os.path.join(root, "nmp-" + name); os.makedirs(p, exist_ok=True)
            print("── %s" % name, flush=True)
            res[name] = measure(a.binary, a.geckodriver, a.port + i, p)
            time.sleep(1)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        for f in (cfg, ls):
            try: os.remove(f)
            except OSError: pass

    json.dump(res, open(a.out, "w"), ensure_ascii=False, indent=2)

    flat = {n: fpdiff.flat(res[n].get("fingerprint")) for n in res}
    keys = sorted(set().union(*[set(v) for v in flat.values()]))
    base = flat["base"]

    print("\n=== 적용 확인 ===")
    for n in CONFIGS:
        p = res[n].get("prefs", {})
        def g(k):
            e = p.get(k, {}); 
            return "%s[%s]" % (e.get("value"), "잠김" if e.get("locked") else "열림")
        print("  %-8s RFP=%-11s LB=%-11s FPP=%-11s 사생활창=%s" % (
            n, g("privacy.resistFingerprinting"),
            g("privacy.resistFingerprinting.letterboxing"),
            g("privacy.fingerprintingProtection"),
            g("browser.privatebrowsing.autostart")))

    print("\n=== 기준선 대비 지문 차이 ===")
    for n in CONFIGS:
        if n == "base":
            continue
        d = [(k, base.get(k, "«없음»"), flat[n].get(k, "«없음»"))
             for k in keys if k.split(".")[0] not in fpdiff.NOISY
             and base.get(k, "«없음»") != flat[n].get(k, "«없음»")]
        print("\n  ── %s" % LABEL[n])
        if not d:
            print("     차이 0 — 지문으로는 기준선과 구별되지 않습니다.")
        for k, b, v in d:
            print("     %-22s 기준선=%-30s → %s" % (k, str(b)[:30], str(v)[:34]))


if __name__ == "__main__":
    main()
