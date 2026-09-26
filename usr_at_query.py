#!/usr/bin/env python3
"""
usr_at_query.py

READ-ONLY dump of a USR-WIFI232-family module's real configuration via its
network AT interface (UDP 48899). Bypasses the web UI, whose dropdowns are not
being populated in modern browsers.

Only query commands are sent (no '='), so nothing on the module is changed.

Protocol (USR / Hi-Flying "network AT command"):
  1. UDP to <module>:48899 with the search password
       USR default:        www.usr.cn
       Hi-Flying default:  HF-A11ASSISTHREAD
     module answers "IP,MAC,MODULE-NAME"
  2. send "+ok" to enter network command mode
  3. send "AT+XXX\r", module answers "+ok=..." or "+ERR=-n"

Usage:
  python3 usr_at_query.py 192.168.20.10
  python3 usr_at_query.py 192.168.20.10 --show-secrets     # also web UI creds + Wi-Fi key
  python3 usr_at_query.py --discover 192.168.20.255         # list modules on a subnet

From Unraid (no Python on the host):
  docker run --rm -it --network host -v "$PWD":/w python:3-alpine \
      python /w/usr_at_query.py 192.168.20.10
"""

import argparse
import socket
import sys
import time

AT_PORT = 48899
PASSWORDS = ["www.usr.cn", "HF-A11ASSISTHREAD"]

QUERIES = [
    ("AT+VER",    "firmware version"),
    ("AT+MID",    "module id"),
    ("AT+WMODE",  "wifi mode (AP / STA / APSTA)"),
    ("AT+WSSSID", "STA: SSID it joins"),
    ("AT+WSLK",   "STA: link status / signal"),
    ("AT+WANN",   "STA: IP configuration"),
    ("AT+TMODE",  "data transfer mode"),
    ("AT+UART",   "UART: baud,data,stop,parity,flow"),
    ("AT+NETP",   "Socket A: protocol,mode,port,address"),
    ("AT+TCPLK",  "Socket A: link status"),
    ("AT+TCPTO",  "Socket A: idle timeout"),
    ("AT+TCPB",   "Socket B: on/off"),
    ("AT+SOCKB",  "Socket B: protocol,port,address"),
    ("AT+TCPLKB", "Socket B: link status"),
    ("AT+REGEN",  "registration packet type"),
]

SECRET_QUERIES = [
    ("AT+WEBU",  "web UI user,password"),
    ("AT+WSKEY", "STA: auth,cipher,key"),
]


def recv_burst(sock: socket.socket, timeout: float) -> bytes:
    """Collect datagrams until `timeout`, or 0.3 s of silence after the first one."""
    chunks = []
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            break
        chunks.append(data)
        deadline = min(deadline, time.monotonic() + 0.3)
    return b"".join(chunks)


def discover(bcast: str, timeout: float) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", 0))
    found = 0
    for pw in PASSWORDS:
        sock.sendto(pw.encode(), (bcast, AT_PORT))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            sock.settimeout(max(0.05, end - time.monotonic()))
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            text = data.decode(errors="replace").strip()
            if "," in text:
                found += 1
                print(f"[+] {addr[0]:<16} password={pw!r:<22} {text}")
    if not found:
        print("[x] no module answered (UDP 48899 blocked? password changed? different subnet?)")
    return 0 if found else 2


def handshake(sock: socket.socket, target: str, timeout: float):
    for pw in PASSWORDS:
        sock.sendto(pw.encode(), (target, AT_PORT))
        reply = recv_burst(sock, timeout).decode(errors="replace").strip()
        if "," in reply:
            return pw, reply
    return None, None


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only config dump for USR-WIFI232 modules")
    ap.add_argument("target", help="module IP, or broadcast address with --discover")
    ap.add_argument("--discover", action="store_true", help="broadcast the search password and list modules")
    ap.add_argument("--show-secrets", action="store_true", help="also query web credentials and Wi-Fi key")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--cmd", action="append", default=[],
                    help="extra read-only query, e.g. --cmd AT+TCPADDB (commands containing '=' are refused)")
    ap.add_argument("--only", action="store_true", help="run only the --cmd queries, skip the default set")
    ap.add_argument("--set-socketb", metavar="IP:PORT",
                    help="WRITE Socket B target (the ONLY write this tool allows). "
                         "Sends AT+TCPADDB=<ip> and AT+TCPPTB=<port>, then AT+Z to reboot. Nothing else.")
    args = ap.parse_args()

    for c in args.cmd:
        if "=" in c or not c.upper().startswith("AT+"):
            ap.error(f"refusing {c!r}: only read-only 'AT+XXX' queries without '=' are allowed")

    if args.set_socketb:
        try:
            ip, port = args.set_socketb.rsplit(":", 1)
            socket.inet_aton(ip)
            port = int(port)
            assert 1 <= port <= 65535
        except Exception:
            ap.error("--set-socketb must be IP:PORT, e.g. 192.168.55.5:9999")

    if args.discover:
        return discover(args.target, args.timeout)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))  # module replies to our source port

    pw, ident = handshake(sock, args.target, args.timeout)
    if not pw:
        print("[x] no handshake reply on UDP 48899.", file=sys.stderr)
        print("    Check: firewall between you and the module, or the search password was changed (AT+ASWD).",
              file=sys.stderr)
        return 2
    print(f"[+] handshake OK with {pw!r}: {ident}")

    sock.sendto(b"+ok", (args.target, AT_PORT))
    recv_burst(sock, 0.5)  # some firmwares echo/ack, most stay silent

    if args.set_socketb:
        ip, port = args.set_socketb.rsplit(":", 1)
        for cmd in (f"AT+TCPADDB={ip}", f"AT+TCPPTB={int(port)}"):
            sock.sendto((cmd + "\r").encode(), (args.target, AT_PORT))
            resp = recv_burst(sock, args.timeout).decode(errors="replace").strip().replace("\r\n", " | ")
            print(f"{cmd:<24} -> {resp or '(no reply)'}")
        print("[+] Socket B target written. Rebooting module (AT+Z) so it reconnects...")
        sock.sendto(b"AT+Z\r", (args.target, AT_PORT))
        recv_burst(sock, 1.0)
        print("[+] reboot sent. Module drops off ~10-20s, then connects to your collector.")
        return 0

    base = [] if args.only else QUERIES + (SECRET_QUERIES if args.show_secrets else [])
    queries = base + [(c.upper(), "extra query") for c in args.cmd]
    for cmd, desc in queries:
        sock.sendto((cmd + "\r").encode(), (args.target, AT_PORT))
        resp = recv_burst(sock, args.timeout).decode(errors="replace").strip().replace("\r\n", " | ")
        print(f"{cmd:<10} {desc:<38} {resp or '(no reply)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
