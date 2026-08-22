#!/usr/bin/env python3
"""레터박싱 판별 시험 — 창을 격자에서 벗어난 크기로 바꾼 뒤 페이지가 보는 값을 읽는다.

레터박싱은 창 크기를 격자에 맞추는 장치다. 창을 안 건드리면 아무 일도 안 하므로,
앞선 시험처럼 고정 크기로만 재면 「차이 0」이 나올 수밖에 없다. 그건 판별력이 없다.

여기서는 창을 1123x777 같은 어중간한 크기로 바꾼다. 레터박싱이 켜져 있으면 페이지가
보는 값은 격자 위 값으로 떨어지고, 꺼져 있으면 어중간한 값이 그대로 보인다.
"""
import importlib.util, json, os, subprocess, sys, tempfile, time, shutil

HERE = os.environ.get("BBIWY_TOOLS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_s = importlib.util.spec_from_file_location("drive", os.path.join(HERE, "leakcheck", "drive.py"))
drive = importlib.util.module_from_spec(_s); _s.loader.exec_module(drive)

BIN = os.environ["BBIWY_BROWSER"]   # 브라우저 실행파일 경로
GD  = os.environ["BBIWY_GECKODRIVER"]  # geckodriver 경로
BDIR = os.path.dirname(BIN)

CFG = '''// NMP
try {
  var name = "on";
  try {
    var d = Components.classes["@mozilla.org/file/directory_service;1"]
              .getService(Components.interfaces.nsIProperties)
              .get("ProfD", Components.interfaces.nsIFile);
    var m = String(d.leafName).match(/nmp-([a-z]+)/); if (m) name = m[1];
  } catch (e) {}
  lockPref("privacy.resistFingerprinting", true);
  lockPref("privacy.resistFingerprinting.letterboxing", name === "on");
  lockPref("nmp.lb", name);
} catch (e) {}
'''
LS = ('pref("general.config.filename", "mozilla.cfg");\n'
      'pref("general.config.obscure_value", 0);\n'
      'pref("general.config.sandbox_enabled", false);\n')

SIZES = [(1123, 777), (1000, 700), (1280, 800)]
READ = """
return {inner:[window.innerWidth, window.innerHeight],
        outer:[window.outerWidth, window.outerHeight],
        screen:[screen.width, screen.height, screen.availWidth, screen.availHeight]};
"""

def run(name, port):
    prof = tempfile.mkdtemp(prefix="nmp-%s-" % name)
    gd = subprocess.Popen([GD, "--port", str(port), "--log", "error"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = []
    try:
        drive.wait_port(port, 30)
        wd = drive.WD(port); wd.start(BIN, prof)
        try:
            wd.ctx("content"); wd.go("data:text/html,<title>lb</title>")
            for w, h in SIZES:
                wd._req("POST", "/session/%s/window/rect" % wd.sid,
                        {"width": w, "height": h, "x": 0, "y": 0})
                time.sleep(1.2)
                r = wd.script(READ)
                out.append(((w, h), r))
        finally:
            wd.quit()
    finally:
        gd.terminate()
        try: gd.wait(timeout=8)
        except Exception: gd.kill()
        shutil.rmtree(prof, ignore_errors=True)
    return out

cfgp = os.path.join(BDIR, "mozilla.cfg")
lsd = os.path.join(BDIR, "defaults", "pref"); os.makedirs(lsd, exist_ok=True)
lsp = os.path.join(lsd, "local-settings.js")
open(cfgp, "w").write(CFG); open(lsp, "w").write(LS)
try:
    res = {n: run(n, 4490 + i) for i, n in enumerate(("on", "off"))}
finally:
    for f in (cfgp, lsp):
        try: os.remove(f)
        except OSError: pass

print("\n%-16s | %-28s | %-28s" % ("요청한 창 크기", "레터박싱 켬 → 페이지가 본 값", "레터박싱 끔 → 페이지가 본 값"))
print("-"*80)
for i, (sz, _) in enumerate(res["on"]):
    a = res["on"][i][1]; b = res["off"][i][1]
    print("%-16s | inner=%-21s | inner=%-21s" % (str(sz), a["inner"], b["inner"]))
    print("%-16s | screen=%-20s | screen=%-20s" % ("", a["screen"][:2], b["screen"][:2]))
same = all(res["on"][i][1]["inner"] == res["off"][i][1]["inner"] for i in range(len(SIZES)))
print("\n판정: 레터박싱 켬/끔이 페이지가 보는 값에 %s" % ("영향 없음" if same else "⚠ 영향 있음"))
grid = all(w % 50 == 0 and h % 50 == 0 for _, r in res["on"] for w, h in [r["inner"]])
print("      레터박싱 켬일 때 값이 50 격자 위인가: %s" % ("예" if grid else "아니오"))
