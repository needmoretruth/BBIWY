#!/usr/bin/env python3
"""mkprofile — 경로 하나에 묶인 프로필과 그 잠금 장치를 만든다.

잠그는 방법이 셋 있고 어느 것이 실제로 먹는지가 단계 0의 질문 하나다.
그래서 셋을 다 만들어 두고 골라 쓴다.

  user.js       프로필 안. 사용자가 지울 수 있다. 잠금이 아니라 기본값 주입이다.
  policies.json 설치 폴더의 distribution/. 기업 정책 경로.
  autoconfig    설치 폴더의 mozilla.cfg + defaults/pref/local-settings.js. lockPref가 여기 산다.

넷째 방법이 하나 더 있다 — 빌드에 들어가는 기본 pref 파일에서 세 번째 인자로 locked를
주는 것이다. Mullvad Browser 자신이 privacy.resistFingerprinting을 그렇게 잠근다.
포크를 만드는 쪽에서는 이게 가장 단순하지만, 빌드를 다시 해야 하므로 여기서는 못 만든다.
"""
import argparse, json, os, shutil, sys

# 경로별로 다른 것은 이 표뿐이다. 나머지 pref는 네 프로필이 전부 같아야 한다 —
# 프로필마다 다른 pref는 곧 지문 차이이기 때문이다.
# kind 는 프록시의 종류다. I2P 는 SOCKS(4447)가 아니라 HTTP(4444)를 쓴다 —
# I2P 프로젝트 자신이 HTTP 프록시를 권하고, 그래야 이름 해석이 라우터 안에서 끝난다.
TRANSPORTS = {
    "direct":  {"proxy": None,                 "kind": None,   "suffix": None,     "webrtc": True},
    "fake":    {"proxy": ("127.0.0.1", 19999), "kind": "socks", "suffix": None,     "webrtc": False},
    "tor":     {"proxy": ("127.0.0.1", 9150),  "kind": "socks", "suffix": ".onion", "webrtc": False},
    "i2p":     {"proxy": ("127.0.0.1", 4444),  "kind": "http",  "suffix": ".i2p",   "webrtc": False},
}

def prefs_for(t, dns_mode):
    c = TRANSPORTS[t]
    p = {}
    if c["proxy"]:
        host, port = c["proxy"]
        # type=1(수동 설정)이어야만 Firefox 의 DNS 가드가 산다. PAC(type=2)와
        # 확장 기반 프록시(proxy.onRequest)는 그 가드를 통과하지 못하므로 금지다.
        p["network.proxy.type"] = 1
        if c["kind"] == "socks":
            p.update({
                "network.proxy.socks": host,
                "network.proxy.socks_port": port,
                "network.proxy.socks_version": 5,
                # ⚠ Firefox 128 에서 갈라졌다. socks_remote_dns 는 이제 SOCKS4 전용이고
                # SOCKS5 를 실제로 지배하는 것은 socks5_remote_dns 다. 실측:
                # socks5_remote_dns=false 로 두면 DNS 가 6패킷 나갔다.
                "network.proxy.socks5_remote_dns": True,
                "network.proxy.socks_remote_dns": True,
            })
        else:
            p.update({
                "network.proxy.http": host, "network.proxy.http_port": port,
                "network.proxy.ssl": host,  "network.proxy.ssl_port": port,
            })
        p.update({
            # ⚠ 이름과 뜻이 어긋나는 설정이다. true 여야 localhost 로 가는 연결도
            # 프록시를 탄다. false 면 localhost 가 프록시 예외가 되어 직접 나간다.
            # 실측으로 확인했다 — Tor Browser 도 true 로 둔다.
            "network.proxy.allow_hijacking_localhost": True,
            "network.proxy.failover_direct": False,
            "network.proxy.allow_bypass": False,
            "network.proxy.no_proxies_on": "",
        })
    else:
        p["network.proxy.type"] = 0

    if not c["webrtc"]:
        p["media.peerconnection.enabled"] = False

    # DNS 처리를 세 갈래로 만들어 어느 쪽이 실제로 새지 않는지 재본다.
    if dns_mode == "off":
        # DNS 하위체계 자체를 끈다. 확장의 browser.dns.resolve 까지 막히는지가 관심사다.
        p["network.dns.disabled"] = True
        p["network.trr.mode"] = 5
    elif dns_mode == "trr-off":
        p["network.trr.mode"] = 5          # DoH 끔
    elif dns_mode == "trr-only":
        p["network.trr.mode"] = 3          # DoH만. 프록시를 타는지가 관심사다.

    # 측정 잡음이 되는 자동 통신을 끈다. 프로토타입 한정 — 제품에서는 다시 따진다.
    p.update({
        "app.update.auto": False,
        "app.update.enabled": False,
        "extensions.update.enabled": False,
        "extensions.update.autoUpdateDefault": False,
        "extensions.blocklist.enabled": False,
        "browser.search.update": False,
        "datareporting.healthreport.uploadEnabled": False,
        "toolkit.telemetry.enabled": False,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        "browser.startup.homepage": "about:blank",
        "browser.newtabpage.enabled": False,
        "browser.shell.checkDefaultBrowser": False,
        "browser.aboutwelcome.enabled": False,
        "security.OCSP.enabled": 0,
        # 첫 요청 전에 미리 연결을 여는 동작. 프록시 판단보다 앞설 수 있어 끈다.
        "network.dns.disablePrefetch": True,
        "network.prefetch-next": False,
        "network.predictor.enabled": False,
        "browser.urlbar.speculativeConnect.enabled": False,
    })
    return p

def write_userjs(path, prefs):
    with open(path, "w") as f:
        f.write("// nmp mkprofile 생성. 잠금이 아니라 기본값 주입이다.\n")
        for k, v in prefs.items():
            f.write('user_pref("%s", %s);\n' % (k, json.dumps(v)))

def write_autoconfig(install_dir, prefs, lock=True):
    cfg = os.path.join(install_dir, "mullvad-browser.cfg")
    with open(cfg, "w") as f:
        f.write("// 첫 줄은 무시된다 — 반드시 주석이어야 한다.\n")
        for k, v in prefs.items():
            f.write('%s("%s", %s);\n' % ("lockPref" if lock else "defaultPref", k, json.dumps(v)))
    d = os.path.join(install_dir, "defaults", "pref")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "local-settings.js"), "w") as f:
        f.write('pref("general.config.filename", "mullvad-browser.cfg");\n')
        f.write('pref("general.config.obscure_value", 0);\n')
        f.write('pref("general.config.sandbox_enabled", false);\n')
    return cfg

def write_policies(install_dir, prefs):
    d = os.path.join(install_dir, "distribution")
    os.makedirs(d, exist_ok=True)
    pol = {"policies": {"Preferences": {}}}
    for k, v in prefs.items():
        pol["policies"]["Preferences"][k] = {"Value": v, "Status": "locked"}
    path = os.path.join(d, "policies.json")
    with open(path, "w") as f:
        json.dump(pol, f, indent=2)
    return path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", required=True, choices=sorted(TRANSPORTS))
    ap.add_argument("--profile", required=True, help="프로필 폴더")
    ap.add_argument("--install", help="설치 폴더 (policies/autoconfig 를 쓸 때)")
    ap.add_argument("--lock", choices=["userjs", "policies", "autoconfig", "all"], default="userjs")
    ap.add_argument("--dns", choices=["default", "off", "trr-off", "trr-only"], default="trr-off")
    ap.add_argument("--socks-port", type=int, help="경로 기본 포트를 덮어쓴다")
    ap.add_argument("--fresh", action="store_true", help="프로필을 지우고 다시 만든다")
    a = ap.parse_args()

    if a.socks_port:
        c = TRANSPORTS[a.transport]
        if c["proxy"]:
            TRANSPORTS[a.transport] = dict(c, proxy=(c["proxy"][0], a.socks_port))

    prefs = prefs_for(a.transport, a.dns)

    if a.fresh and os.path.isdir(a.profile):
        shutil.rmtree(a.profile)
    os.makedirs(a.profile, exist_ok=True)

    made = []
    if a.lock in ("userjs", "all"):
        write_userjs(os.path.join(a.profile, "user.js"), prefs)
        made.append("user.js")
    if a.lock in ("policies", "all"):
        if not a.install:
            sys.exit("--install 이 필요합니다")
        made.append(write_policies(a.install, prefs))
    if a.lock in ("autoconfig", "all"):
        if not a.install:
            sys.exit("--install 이 필요합니다")
        made.append(write_autoconfig(a.install, prefs))

    print("경로=%s  프로필=%s  DNS=%s" % (a.transport, a.profile, a.dns))
    print("설정 %d개 · 생성: %s" % (len(prefs), ", ".join(made)))

main()
