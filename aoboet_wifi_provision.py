#!/usr/bin/env python3
"""
aoboet_wifi_provision.py

Provision the AOBOET battery Wi-Fi module onto your network WITHOUT the AoBoET app
and without any cloud account.

Protocol source: com.demo.smarthome.activity.UserLinkActivity / SearchSSID / Tool
in nickAS21/aoboet_java. It is the USR-IOT "USR-WIFI232 fast access Wi-Fi" protocol:

  frame   = FF | LEN_HI | LEN_LO | PAYLOAD... | CHECKSUM
  checksum = sum(LEN_HI .. last payload byte) & 0xFF   (head byte 0xFF excluded)

  0x01  search      phone -> module   FF 00 01 01 02
  0x81  scan result module -> phone   FF LL LL 81 <count> [SSID 00 <signal%> 0D 0A]... CS
  0x02  set         phone -> module   FF LL LL 02 00 <SSID> 0D 0A <PASSWORD> CS
  0x82  set result  module -> phone   FF 00 03 82 <ssid_ok> <pwd_ok> CS

Transport: UDP broadcast to 255.255.255.255:49000, replies come back to UDP 26000.

Usage (laptop joined to the battery module's OWN access point, other NICs down):
  python3 aoboet_wifi_provision.py --scan
  python3 aoboet_wifi_provision.py --ssid "IoT-2G" --password 'secret'
  python3 aoboet_wifi_provision.py --ssid "IoT-2G" --password 'secret' --bcast 10.10.100.255
"""

import argparse
import getpass
import socket
import sys
import time

TARGET_PORT = 49000  # module listens here while in AP/config mode
LOCAL_PORT = 26000   # the original app binds this port and the module answers to it

CMD_SEARCH = 0x01
CMD_SET = 0x02
RSP_SEARCH = 0x81
RSP_SET = 0x82


def build_frame(payload: bytes) -> bytes:
    length = len(payload)
    body = bytes([(length >> 8) & 0xFF, length & 0xFF]) + payload
    return b"\xFF" + body + bytes([sum(body) & 0xFF])


def frame_is_valid(pkt: bytes) -> bool:
    if len(pkt) < 5 or pkt[0] != 0xFF:
        return False
    declared = (pkt[1] << 8) | pkt[2]
    if declared != len(pkt) - 4:
        return False
    return (sum(pkt[1:-1]) & 0xFF) == pkt[-1]


def parse_scan(pkt: bytes):
    """Return list of (ssid, signal_percent) from a 0x81 response."""
    data = pkt[5:-1]  # skip FF LL LL 81 <count>, drop checksum
    results = []
    for entry in data.split(b"\r\n"):
        if len(entry) < 2:
            continue
        ssid = entry[:-2].decode("utf-8", errors="replace")  # entry = SSID 00 <signal>
        results.append((ssid, entry[-1]))
    return results


def self_test() -> None:
    # Examples taken from the USR WIFI232-A2 user manual, section "Fast access Wi-Fi".
    assert build_frame(bytes([CMD_SEARCH])) == bytes.fromhex("FF00010102")
    expected_set = bytes.fromhex("FF000F02005445535431 0D0A 313233343536 CE".replace(" ", ""))
    assert build_frame(b"\x02\x00" + b"TEST1\r\n123456") == expected_set
    sample = bytes.fromhex("FF0014810254455354310040 0D0A 544553543200370D0A1F".replace(" ", ""))
    assert frame_is_valid(sample)
    assert parse_scan(sample) == [("TEST1", 0x40), ("TEST2", 0x37)]
    assert frame_is_valid(bytes.fromhex("FF0003820101 87".replace(" ", "")))


def open_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind to 0.0.0.0 on purpose: a socket bound to a unicast IP will not receive broadcast replies on Linux.
    sock.bind(("", LOCAL_PORT))
    return sock


def wait_for(sock: socket.socket, wanted_cmd: int, timeout: float):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, None
        sock.settimeout(remaining)
        try:
            pkt, addr = sock.recvfrom(2048)
        except socket.timeout:
            return None, None
        if pkt and pkt[0] == 0xFF and len(pkt) > 3 and pkt[3] == wanted_cmd:
            if not frame_is_valid(pkt):
                print(f"[!] bad checksum/length from {addr[0]}: {pkt.hex(' ')}", file=sys.stderr)
                continue
            return pkt, addr


def send_with_retries(sock, frame, bcast, wanted_cmd, retries, timeout):
    for attempt in range(1, retries + 1):
        sock.sendto(frame, (bcast, TARGET_PORT))
        pkt, addr = wait_for(sock, wanted_cmd, timeout)
        if pkt:
            return pkt, addr
        print(f"[.] no 0x{wanted_cmd:02X} reply (attempt {attempt}/{retries})", file=sys.stderr)
    return None, None


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision AOBOET battery Wi-Fi module without the app")
    ap.add_argument("--scan", action="store_true", help="only list SSIDs the module can see")
    ap.add_argument("--ssid", help="2.4 GHz WPA2-PSK SSID the module should join")
    ap.add_argument("--password", help="Wi-Fi password (prompted if omitted)")
    ap.add_argument("--bcast", default="255.255.255.255",
                    help="broadcast address (use the module AP subnet broadcast if you have several NICs)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    self_test()

    if not args.scan and not args.ssid:
        ap.error("use --scan or --ssid")

    sock = open_socket()

    # 1) Search: proves the module is reachable and shows what it can see.
    pkt, addr = send_with_retries(sock, build_frame(bytes([CMD_SEARCH])), args.bcast,
                                  RSP_SEARCH, args.retries, args.timeout)
    if not pkt:
        print("[x] module did not answer. Are you on its AP? Is another NIC stealing the broadcast?",
              file=sys.stderr)
        return 2

    print(f"[+] module at {addr[0]} sees {pkt[4]} network(s):")
    seen = parse_scan(pkt)
    for ssid, signal in seen:
        print(f"    {signal:3d}%  {ssid}")

    if args.scan:
        return 0

    if args.ssid not in {s for s, _ in seen}:
        print(f"[!] '{args.ssid}' is not in the module's scan list (hidden SSID / 5 GHz only / out of range?)",
              file=sys.stderr)

    password = args.password if args.password is not None else getpass.getpass("Wi-Fi password: ")

    # 2) Set SSID + password. Payload: 02 00 SSID \r\n PASSWORD
    payload = bytes([CMD_SET, 0x00]) + args.ssid.encode("utf-8") + b"\r\n" + password.encode("utf-8")
    pkt, addr = send_with_retries(sock, build_frame(payload), args.bcast,
                                  RSP_SET, args.retries, args.timeout)
    if not pkt:
        print("[x] no confirmation from module", file=sys.stderr)
        return 3

    ssid_ok, pwd_ok = pkt[4], pkt[5]
    print(f"[+] module reply: ssid_found={ssid_ok} password_format_ok={pwd_ok}")
    if ssid_ok == 1 and pwd_ok == 1:
        print("[+] accepted. The module should restart in STA mode and request a DHCP lease on your network.")
        return 0
    if ssid_ok == 0:
        print("[x] module says the SSID does not exist", file=sys.stderr)
    if pwd_ok == 0:
        print("[x] module rejected the password format (length / charset)", file=sys.stderr)
    return 4


if __name__ == "__main__":
    sys.exit(main())
