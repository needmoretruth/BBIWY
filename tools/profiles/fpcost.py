#!/usr/bin/env python3
"""fpcost — what does making the daily profile usable actually cost?

If every profile is built on the same base, is there any reason for the daily

one to carry a different fingerprint? The answer depends entirely on *which*
relaxation: some are invisible to a page and therefore free, others become a
fingerprint difference immediately. This draws that line with numbers instead
of assumptions.

The baseline is the shipped default (RFP locked, letterboxing on); everything
else is compared against it.
"""
import argparse, importlib.util, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "drive", os.path.join(HERE, "..", "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drive)
sys.path.insert(0, os.path.join(HERE, "..", "leakcheck"))
import fpdiff

# Profile directory name -> the configuration autoconfig selects.
CONFIGS = ["base", "nolb", "persist", "norfp"]
LABEL = {
    "base":    "baseline — shipped default (RFP locked + letterboxing)",
    "nolb":    "letterboxing off only (RFP still locked)",
    "persist": "logins and history persist (RFP and letterboxing unchanged)",
    "norfp":   "RFP off, FPP on",
}

MOZILLA_CFG = r'''// autoconfig — the first line must be a comment
try {
  var name = "base";
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    var m = String(d.leafName).match(/nmp-([a-z]+)/);
    if (m) name = m[1];
  } catch (e) {}
  lockPref("bbiwy.config", name);

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
    // Most of what "usable" means lives here: logins persist, history persists,
    // nothing is wiped on exit.
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

WATCH = ["bbiwy.config", "privacy.resistFingerprinting",
         "privacy.resistFingerprinting.letterboxing",
         "privacy.fingerprintingProtection",
         "browser.privatebrowsing.autostart", "signon.rememberSignons"]


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

    root = tempfile.mkdtemp(prefix="bbiwy-fpcost-")
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

    print("\n=== confirm the prefs took effect ===")
    for n in CONFIGS:
        p = res[n].get("prefs", {})
        def g(k):
            e = p.get(k, {}); 
            return "%s[%s]" % (e.get("value"), "locked" if e.get("locked") else "open")
        print("  %-8s RFP=%-11s LB=%-11s FPP=%-11s private-window=%s" % (
            n, g("privacy.resistFingerprinting"),
            g("privacy.resistFingerprinting.letterboxing"),
            g("privacy.fingerprintingProtection"),
            g("browser.privatebrowsing.autostart")))

    print("\n=== fingerprint difference against the baseline ===")
    for n in CONFIGS:
        if n == "base":
            continue
        d = [(k, base.get(k, "<absent>"), flat[n].get(k, "<absent>"))
             for k in keys if k.split(".")[0] not in fpdiff.NOISY
             and base.get(k, "<absent>") != flat[n].get(k, "<absent>")]
        print("\n  ── %s" % LABEL[n])
        if not d:
            print("     zero differences — indistinguishable from the baseline.")
        for k, b, v in d:
            print("     %-22s baseline=%-30s -> %s" % (k, str(b)[:30], str(v)[:34]))


if __name__ == "__main__":
    main()
