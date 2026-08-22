#!/usr/bin/env python3
"""locktest — 한 설치본이 프로필마다 pref를 다른 값으로 잠글 수 있는가.

오너가 정한 프로필 구성(프라이버시 4개는 지문 통일 · 데일리 1개만 별도 지문)이
실제로 구현 가능한지가 여기서 갈린다. autoconfig는 설치 단위인데, 우리는 프로필
단위로 다른 잠금이 필요하다. 다리를 놓을 수 있는 유일한 후보가 getenv()다.

autoconfig 파일을 넣고 → 환경변수만 바꿔 두 번 띄우고 → chrome 권한으로
prefIsLocked 를 물어본다. 표준 라이브러리만 쓴다.
"""
import argparse, importlib.util, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drive)

WATCH = [
    "privacy.resistFingerprinting",
    "privacy.fingerprintingProtection",
    "nmp.profile.class",
    "nmp.autoconfig.ran",
    "nmp.autoconfig.getenv_works",
    "nmp.autoconfig.services_reachable",
    "nmp.autoconfig.profile_path",
]

MOZILLA_CFG = r'''// NMP autoconfig — 첫 줄은 반드시 주석이어야 한다 (파서가 한 줄 버린다)
try {
  lockPref("nmp.autoconfig.ran", true);

  // (1) getenv 가 있는가 — 프로필별 분기의 유일한 다리 후보
  var klass = "«getenv없음»";
  try {
    klass = getenv("NMP_PROFILE_CLASS") || "«빈값»";
    lockPref("nmp.autoconfig.getenv_works", true);
  } catch (e) {
    lockPref("nmp.autoconfig.getenv_works", false);
  }
  lockPref("nmp.profile.class", klass);

  // (2) 이 시점에 프로필 경로를 알 수 있는가 — 알 수 있으면 getenv 없이도 분기 가능
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    lockPref("nmp.autoconfig.services_reachable", true);
    lockPref("nmp.autoconfig.profile_path", String(d.path));
  } catch (e) {
    lockPref("nmp.autoconfig.services_reachable", false);
    lockPref("nmp.autoconfig.profile_path", "«실패: " + e + "»");
  }

  // (3) 본론 — 부류에 따라 지문 방어를 다르게 잠근다
  if (klass === "daily") {
    unlockPref("privacy.resistFingerprinting");
    defaultPref("privacy.resistFingerprinting", false);
    lockPref("privacy.fingerprintingProtection", true);
  } else {
    lockPref("privacy.resistFingerprinting", true);
    lockPref("privacy.fingerprintingProtection", false);
  }
} catch (e) {
  try { lockPref("nmp.autoconfig.ran", false); } catch (e2) {}
}
'''

LOCAL_SETTINGS = ('pref("general.config.filename", "mozilla.cfg");\n'
                  'pref("general.config.obscure_value", 0);\n'
                  'pref("general.config.sandbox_enabled", %s);\n')


def install_autoconfig(browser_dir, sandbox):
    cfg = os.path.join(browser_dir, "mozilla.cfg")
    ls_dir = os.path.join(browser_dir, "defaults", "pref")
    os.makedirs(ls_dir, exist_ok=True)
    ls = os.path.join(ls_dir, "local-settings.js")
    with open(cfg, "w") as f:
        f.write(MOZILLA_CFG)
    with open(ls, "w") as f:
        f.write(LOCAL_SETTINGS % ("true" if sandbox else "false"))
    return [cfg, ls]


def run_once(binary, gecko, port, klass, sandbox, browser_dir):
    made = install_autoconfig(browser_dir, sandbox)
    prof = tempfile.mkdtemp(prefix="nmp-lock-")
    env = dict(os.environ)
    env["NMP_PROFILE_CLASS"] = klass
    gd = subprocess.Popen([gecko, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        if not drive.wait_port(port, 30):
            return {"«오류»": "geckodriver 가 뜨지 않았습니다"}
        wd = drive.WD(port)
        wd.start(binary, prof)
        try:
            wd.ctx("chrome")
            return wd.script(drive.PREF_DUMP, [WATCH])
        finally:
            wd.quit()
    finally:
        gd.terminate()
        try: gd.wait(timeout=10)
        except Exception: gd.kill()
        shutil.rmtree(prof, ignore_errors=True)
        for p in made:
            try: os.remove(p)
            except OSError: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--geckodriver", required=True)
    ap.add_argument("--port", type=int, default=4460)
    ap.add_argument("--out")
    a = ap.parse_args()

    browser_dir = os.path.dirname(os.path.abspath(a.binary))
    results = {}
    for sandbox in (True, False):
        for klass in ("privacy", "daily"):
            key = "sandbox=%s klass=%s" % (sandbox, klass)
            print("── %s" % key, flush=True)
            results[key] = run_once(a.binary, a.geckodriver, a.port, klass,
                                    sandbox, browser_dir)
            a.port += 1
            time.sleep(1)

    print(json.dumps(results, ensure_ascii=False, indent=2))
    if a.out:
        with open(a.out, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
