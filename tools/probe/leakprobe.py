#!/usr/bin/env python3
"""leakprobe — a deliberate leak generator, to prove the harness is not blind.

Run this before attaching a browser. It causes known leaks on purpose and
checks that the counters move, then uses only the permitted route and checks
that they stay still. If the first does not move, the harness is blind. If the
second does, it is jumping at shadows. Both have to hold before its verdicts
mean anything.
"""
import argparse, socket, struct, sys, time

def r(name, ok, detail=""):
    print("%-14s %-9s %s" % (name, "got out" if ok else "blocked", detail))
    return ok

def p_getaddrinfo(host):
    try:
        info = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return r("resolve", True, "%s -> %s" % (host, info[0][4][0]))
    except Exception as e:
        return r("resolve", False, str(e)[:60])

def p_dns_udp(server, host):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for part in host.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, (server, 53)); s.recvfrom(512)
        return r("DNS/udp", True, "%s answered" % server)
    except Exception as e:
        return r("DNS/udp", False, "%s: %s" % (server, str(e)[:40]))
    finally:
        s.close()

def p_udp(name, host, port, payload=b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(payload, (host, port)); s.recvfrom(512)
        return r(name, True, "%s:%d answered" % (host, port))
    except socket.timeout:
        return r(name, True, "%s:%d sent, no reply" % (host, port))
    except Exception as e:
        return r(name, False, str(e)[:50])
    finally:
        s.close()

def p_tcp(host, port):
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((host, port))
        return r("TCP direct", True, "%s:%d" % (host, port))
    except Exception as e:
        return r("TCP direct", False, str(e)[:50])
    finally:
        s.close()

def p_socks(proxy, host, port):
    ph, pp = proxy.split(":")
    s = socket.socket(); s.settimeout(6)
    try:
        s.connect((ph, int(pp)))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return r("via SOCKS", False, "handshake refused")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
        rep = s.recv(10)
        if len(rep) >= 2 and rep[1] == 0:
            return r("via SOCKS", True, "%s:%d connected" % (host, port))
        return r("via SOCKS", False, "refused, code %s" % (rep[1] if len(rep) > 1 else "?"))
    except Exception as e:
        return r("via SOCKS", False, str(e)[:50])
    finally:
        s.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="example.com")
    ap.add_argument("--dns-server", default="9.9.9.9")
    ap.add_argument("--ip", default="93.184.215.14", help="address to hit without resolving")
    ap.add_argument("--socks", help="HOST:PORT — exercise the permitted route")
    ap.add_argument("--only", help="comma-separated subset: dns,dnsudp,stun,quic,tcp,socks")
    a = ap.parse_args()
    want = set(a.only.split(",")) if a.only else None
    def on(k): return want is None or k in want

    print("== deliberate leak probe ==")
    if on("dns"):    p_getaddrinfo(a.host)
    if on("dnsudp"): p_dns_udp(a.dns_server, a.host)
    if on("stun"):   p_udp("STUN/udp", "74.125.250.129", 19302)
    if on("quic"):   p_udp("QUIC/udp", a.ip, 443, b"\xc0" + b"\x00" * 40)
    if on("tcp"):    p_tcp(a.ip, 443)
    if on("socks") and a.socks: p_socks(a.socks, a.host, 80)
    print("\nnow read the counters: nmplab.sh verdict <name>")

main()
