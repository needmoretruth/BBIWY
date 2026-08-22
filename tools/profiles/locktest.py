#!/usr/bin/env python3
"""locktest — can one installation lock a pref to different values per profile?

This is the question the five-profile design turns on. Autoconfig is
installation-wide, but the locks have to differ per profile. getenv() is the
only candidate for bridging the two.

Install the autoconfig files, launch twice changing only an environment
variable, then ask prefIsLocked from chrome scope. Standard library only.
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
    "bbiwy.profile.class",
    "bbiwy.autoconfig.ran",
    "bbiwy.autoconfig.getenv_works",
    "bbiwy.autoconfig.services_reachable",
    "bbiwy.autoconfig.profile_path",
]

MOZILLA_CFG = r'''// autoconfig — the first line must be a comment; the parser discards it
try {
  lockPref("bbiwy.autoconfig.ran", true);

  // (1) Does getenv exist? The only candidate bridge to per-profile branching.
  var klass = "<no getenv>";
  try {
    klass = getenv("BBIWY_PROFILE_CLASS") || "<empty>";
    lockPref("bbiwy.autoconfig.getenv_works", true);
  } catch (e) {
    lockPref("bbiwy.autoconfig.getenv_works", false);
  }
  lockPref("bbiwy.profile.class", klass);

  // (2) Is the profile path knowable here? If so, branching needs no env var.
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    lockPref("bbiwy.autoconfig.services_reachable", true);
    lockPref("bbiwy.autoconfig.profile_path", String(d.path));
  } catch (e) {
    lockPref("bbiwy.autoconfig.services_reachable", false);
    lockPref("bbiwy.autoconfig.profile_path", "<failed: " + e + ">");
  }

  // (3) The actual question: lock the defence differently per class.
  if (klass === "daily") {
    unlockPref("privacy.resistFingerprinting");
    defaultPref("privacy.resistFingerprinting", false);
    lockPref("privacy.fingerprintingProtection", true);
  } else {
    lockPref("privacy.resistFingerprinting", true);
    lockPref("privacy.fingerprintingProtection", false);
  }
} catch (e) {
  try { lockPref("bbiwy.autoconfig.ran", false); } catch (e2) {}
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
    prof = tempfile.mkdtemp(prefix="bbiwy-lock-")
    env = dict(os.environ)
    env["BBIWY_PROFILE_CLASS"] = klass
    gd = subprocess.Popen([gecko, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        if not drive.wait_port(port, 30):
            return {"<error>": "geckodriver did not start"}
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
