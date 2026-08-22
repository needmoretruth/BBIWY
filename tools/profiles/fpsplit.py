#!/usr/bin/env python3
"""fpsplit — does the fingerprint actually split the way the design says?

This harness dates from an earlier design in which four privacy profiles shared
a fingerprint and the daily profile had its own. That design was later changed —
see fpcost.py, which measured that the split costs more than it buys — but the
two properties this checks are still the right ones to check.

It measures two things:
  unified    do the privacy profiles differ by nothing?
  separated  is the daily profile genuinely different from them? (If not, there
             was no point building it separately.)

Branching is on the *running profile's actual path*, not on an environment
variable: a user can set a variable, and a lock a user can lift is not a lock.
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

# The class is decided by the last component of the running profile path.
MOZILLA_CFG = r'''// autoconfig — the first line must be a comment
try {
  var klass = "privacy";
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    if (/(^|[\/\-])daily([\-\.]|$)/.test(String(d.leafName))) klass = "daily";
    lockPref("nmp.profile.path", String(d.path));
  } catch (e) {
    // If the path cannot be read, fall to the safe side and lock as privacy.
    lockPref("bbiwy.profile.path", "<failed>");
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
            return {"<error>": "geckodriver did not start"}
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
    root = tempfile.mkdtemp(prefix="bbiwy-fpsplit-")
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

    # ── verdict ─────────────────────────────────────────────
    flat = {n: fpdiff.flat(results[n].get("fingerprint")) for n in results}
    keys = sorted(set().union(*[set(v) for v in flat.values()]))

    print("\n=== lock state ===")
    for n in PROFILES:
        p = results[n].get("prefs", {})
        rfp = p.get("privacy.resistFingerprinting", {})
        fpp = p.get("privacy.fingerprintingProtection", {})
        print("  %-9s class=%-8s RFP=%-5s[%s]  FPP=%-5s[%s]" % (
            n, p.get("nmp.profile.class", {}).get("value"),
            rfp.get("value"), "locked" if rfp.get("locked") else "open",
            fpp.get("value"), "locked" if fpp.get("locked") else "open"))

    print("\n=== unified: differences among the privacy profiles ===")
    unified_break = []
    for k in keys:
        if k.split(".")[0] in fpdiff.NOISY:
            continue
        vals = {flat[n].get(k, "<absent>") for n in PRIVACY}
        if len(vals) > 1:
            unified_break.append((k, {n: flat[n].get(k) for n in PRIVACY}))
    if not unified_break:
        print("  zero differences — they cannot be told apart.")
    else:
        for k, v in unified_break:
            print("  ⛔ %s → %s" % (k, v))

    print("\n=== separated: where daily differs ===")
    sep = []
    for k in keys:
        if k.split(".")[0] in fpdiff.NOISY:
            continue
        base = flat["hardened"].get(k, "<absent>")
        d = flat["daily"].get(k, "<absent>")
        if base != d:
            sep.append((k, base, d))
    if not sep:
        print("  zero differences — building daily separately bought nothing.")
    else:
        for k, b, d in sep:
            print("  %-28s privacy=%s  daily=%s" % (k, str(b)[:34], str(d)[:34]))

    print("\n=== verdict ===")
    print("  unified   (privacy profiles identical): %s" % ("pass" if not unified_break else "FAIL"))
    print("  separated (daily genuinely differs):   %s" % ("pass" if sep else "FAIL"))


if __name__ == "__main__":
    main()
