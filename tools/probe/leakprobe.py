#!/usr/bin/env python3
"""leakprobe — 하네스가 실제로 빨간불을 켜는지 시험하기 위한 누수 유발기.

브라우저를 붙이기 전에 이것부터 돌린다. 알려진 누수를 일부러 일으켜
계수기가 올라가는지 보고, 허용 경로만 쓰는 동작에서는 계수기가 그대로인지 본다.
전자가 안 올라가면 하네스가 눈먼 것이고, 후자가 올라가면 하네스가 과민한 것이다.
둘 다 확인해야 이 실험대의 판정을 신뢰할 수 있다.
"""
import argparse, socket, struct, sys, time

def r(name, ok, detail=""):
    print("%-14s %-9s %s" % (name, "성공" if ok else "차단/실패", detail))
    return ok

def p_getaddrinfo(host):
    try:
        info = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return r("이름해석", True, "%s -> %s" % (host, info[0][4][0]))
    except Exception as e:
        return r("이름해석", False, str(e)[:60])

def p_dns_udp(server, host):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for part in host.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, (server, 53)); s.recvfrom(512)
        return r("DNS/udp", True, "%s 응답함" % server)
    except Exception as e:
        return r("DNS/udp", False, "%s: %s" % (server, str(e)[:40]))
    finally:
        s.close()

def p_udp(name, host, port, payload=b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(payload, (host, port)); s.recvfrom(512)
        return r(name, True, "%s:%d 응답함" % (host, port))
    except socket.timeout:
        return r(name, True, "%s:%d 발신은 됨(응답없음)" % (host, port))
    except Exception as e:
        return r(name, False, str(e)[:50])
    finally:
        s.close()

def p_tcp(host, port):
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((host, port))
        return r("TCP직접", True, "%s:%d" % (host, port))
    except Exception as e:
        return r("TCP직접", False, str(e)[:50])
    finally:
        s.close()

def p_socks(proxy, host, port):
    ph, pp = proxy.split(":")
    s = socket.socket(); s.settimeout(6)
    try:
        s.connect((ph, int(pp)))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return r("SOCKS경유", False, "핸드셰이크 거절")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
        rep = s.recv(10)
        if len(rep) >= 2 and rep[1] == 0:
            return r("SOCKS경유", True, "%s:%d 연결" % (host, port))
        return r("SOCKS경유", False, "거절 코드 %s" % (rep[1] if len(rep) > 1 else "?"))
    except Exception as e:
        return r("SOCKS경유", False, str(e)[:50])
    finally:
        s.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="example.com")
    ap.add_argument("--dns-server", default="9.9.9.9")
    ap.add_argument("--ip", default="93.184.215.14", help="이름해석 없이 직접 칠 주소")
    ap.add_argument("--socks", help="HOST:PORT — 허용 경로 시험")
    ap.add_argument("--only", help="쉼표로 고른 항목만: dns,dnsudp,stun,quic,tcp,socks")
    a = ap.parse_args()
    want = set(a.only.split(",")) if a.only else None
    def on(k): return want is None or k in want

    print("== 누수 유발 시험 ==")
    if on("dns"):    p_getaddrinfo(a.host)
    if on("dnsudp"): p_dns_udp(a.dns_server, a.host)
    if on("stun"):   p_udp("STUN/udp", "74.125.250.129", 19302)
    if on("quic"):   p_udp("QUIC/udp", a.ip, 443, b"\xc0" + b"\x00" * 40)
    if on("tcp"):    p_tcp(a.ip, 443)
    if on("socks") and a.socks: p_socks(a.socks, a.host, 80)
    print("\n계수기 판정: nmplab.sh verdict <이름>")

main()
