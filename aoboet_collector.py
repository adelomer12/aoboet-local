#!/usr/bin/env python3
"""
aoboet_collector.py

Passive local reader for an AOBOET LFP battery whose USR-WIFI232 module is set to
mirror its serial stream to a second TCP socket (Socket B) pointed at this host.

It NEVER transmits on the battery socket. Bytes sent back to Socket B would be
forwarded to the BMS UART, so this side is receive-only by design.

Protocol (reverse-engineered from a packet capture; see notes at bottom):
  frame  = AA 55 | TYPE(1) | DEVICE-ID(19 ASCII) | BODY | CRC16(2, big-endian)
  CRC    = CRC-16/ARC  (poly 0x8005, init 0x0000, refin, refout, xorout 0x0000)
           computed over everything from AA 55 through the last body byte.

  Device IDs seen: '1415720B...' = battery/BMS node, '1415720S...' = inverter/system node.

  TYPE 0xC1 (battery, 16S here):
     28 10 | 16 x uint16-BE cell mV | field16(u16-BE, SOC-correlated) | SOC(u8)
          | 00 00 00 00 | 0E 0F (two bytes, likely temperatures) | CRC
     Confirmed: per-cell mV, cell count (0x10=16), SOC byte.
     Pack voltage is taken as the sum of cell voltages (matches Luxpower reading).
     field16 and the 0E/0F bytes are exposed raw and NOT trusted as engineering
     units until you confirm them against Home Assistant / the inverter.

  TYPE 0xC0 (inverter/system): exposed raw for now.
  TYPE 0xA2 / 0xB1 / 0xD0: heartbeats / clock — ignored.

Modes:
  --raw            just dump decoded frames to stdout (no MQTT). Use this first.
  (default)        decode and publish to MQTT with HA autodiscovery.

MQTT deps only needed for publishing:  pip install paho-mqtt

Run on Unraid (Socket B target = this host:9999):
  docker run -d --name aoboet --restart unless-stopped --network host \
      -v /mnt/user/appdata/aoboet:/app -w /app python:3-alpine sh -c \
      "pip install --quiet paho-mqtt && python aoboet_collector.py \
         --mqtt-host 192.168.55.11 --mqtt-user USER --mqtt-pass PASS"

Discovery first (no MQTT, just watch frames):
  docker run --rm -it --network host -v /mnt/user/appdata/aoboet:/app -w /app \
      python:3-alpine python aoboet_collector.py --raw
"""

import argparse
import json
import socket
import struct
import sys
import time

HEADER = b"\xAA\x55"
T_BATT = 0xC1
T_INV = 0xC0
ID_LEN = 19  # ASCII device id

# Temperature calibration: the c0 probe bytes read (raw + TEMP_OFFSET) degrees C.
# Anchored from Luxpower: raw byte 9 == 31 C -> offset +22. Override with --temp-offset
# if your Luxpower reading disagrees (re-anchor: offset = luxpower_C - c0_b12_raw).
TEMP_OFFSET = 22


# ---------- CRC-16/ARC ----------
def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


# ---------- stream framer ----------
class Framer:
    """Accumulates bytes and yields complete, CRC-valid frames.

    Frame length isn't in a header field, so we locate the next AA 55, treat the
    span up to the following AA 55 as a candidate, and accept it only if its last
    two bytes are a valid big-endian CRC over the rest. This tolerates an AA 55
    that happens to occur inside a body: that split fails CRC and we resync.
    """

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf.extend(data)
        out = []
        while True:
            start = self.buf.find(HEADER)
            if start < 0:
                # keep only a trailing partial header byte
                self.buf = self.buf[-1:] if self.buf[-1:] == b"\xAA" else bytearray()
                break
            if start:
                del self.buf[:start]  # drop junk before header
            nxt = self.buf.find(HEADER, 2)
            if nxt < 0:
                # No following header yet. If what we have is itself a complete,
                # CRC-valid frame, emit it now instead of waiting for the next AA55.
                whole = bytes(self.buf)
                if self._valid(whole):
                    out.append(whole)
                    self.buf = bytearray()
                break  # otherwise need more bytes to know where this frame ends
            cand = bytes(self.buf[:nxt])
            if self._valid(cand):
                out.append(cand)
                del self.buf[:nxt]
            else:
                # try extending: the AA55 we found may be inside the body
                extended = self._try_extend(nxt)
                if extended is None:
                    # give up on this header, skip past it and resync
                    del self.buf[:2]
                else:
                    out.append(extended[0])
                    del self.buf[: extended[1]]
        return out

    def _valid(self, frame: bytes) -> bool:
        if len(frame) < 3 + ID_LEN + 2:
            return False
        return crc16_arc(frame[:-2]) == struct.unpack(">H", frame[-2:])[0]

    def _try_extend(self, from_idx):
        idx = from_idx
        for _ in range(8):  # look a few AA55 boundaries ahead
            nxt = self.buf.find(HEADER, idx + 2)
            if nxt < 0:
                return None
            cand = bytes(self.buf[:nxt])
            if self._valid(cand):
                return cand, nxt
            idx = nxt
        return None


# ---------- decoders ----------
def decode_batt(frame: bytes):
    body = frame[3 + ID_LEN : -2]
    if len(body) < 2:
        return None
    ncell = body[1]
    need = 2 + 2 * ncell + 1  # prefix + cells + SOC (minimum we rely on)
    if len(body) < need:
        return None
    cells = [struct.unpack(">H", body[2 + 2 * i : 4 + 2 * i])[0] for i in range(ncell)]
    off = 2 + 2 * ncell
    field16 = struct.unpack(">H", body[off : off + 2])[0] if len(body) >= off + 2 else None
    soc = body[off + 2] if len(body) >= off + 3 else None
    tail = body[off + 3 :].hex(" ")
    dev = frame[3 : 3 + ID_LEN].decode("ascii", "replace")
    pack_mv = sum(cells)
    return {
        "device": dev,
        "cell_count": ncell,
        "cells_mv": cells,
        "cell_min_mv": min(cells),
        "cell_max_mv": max(cells),
        "cell_delta_mv": max(cells) - min(cells),
        "cell_avg_mv": round(sum(cells) / ncell, 1),
        "pack_voltage_v": round(pack_mv / 1000.0, 2),
        "soc_pct": soc,
        "raw_field16": field16,
        "raw_tail": tail,
    }


def decode_inv(frame: bytes):
    """S-node / inverter frame. Confirmed: pack voltage, SOC. Provisional: current, temps.

    Layout of body (after 19-byte id), for the 21-byte form seen in captures:
      [0:2]  const 0x1400
      [2:4]  pack voltage, u16-BE, /100 -> V   (matches c1 cell-sum and Luxpower)
      [4:6]  field4, u16-BE  -> looks like current /10 (A); sign unconfirmed
      [6]    SOC %           (cross-checks c1 SOC)
      [7]    00
      [8:12] 01 00 00 00
      [12]   temp probe A (provisional)
      [13:16]00 00 00
      [16]   temp probe B (provisional)
      rest   zero padding
    Everything past SOC is exposed raw until confirmed against the inverter.
    """
    body = frame[3 + ID_LEN : -2]
    dev = frame[3 : 3 + ID_LEN].decode("ascii", "replace")
    out = {"device": dev, "raw_hex": body.hex(" ")}
    if len(body) >= 7:
        out["pack_voltage_v"] = round(struct.unpack(">H", body[2:4])[0] / 100.0, 2)
        # current: signed int16 BE, /10.  positive = charge, negative = discharge.
        # confirmed across a charge->discharge transition (+24.1 A vs -20.1 A).
        cur = struct.unpack(">h", body[4:6])[0] / 10.0
        out["current_a"] = round(cur, 1)
        out["charging"] = cur > 0
        out["soc_pct"] = body[6]
    if len(body) >= 17:
        # Bytes 12 and 16 were once thought to be temperature probes, but a wider
        # range disproved it: at LXP 31/33/38 C they read 9/11/47 and 9/10/20 — they
        # scale with charge current/SOC, not temperature. Battery temperature is NOT
        # in the c0 frame; use the Luxpower BMS temperature sensor instead. These two
        # bytes (charge-related, exact meaning TBD) are exposed raw only.
        out["c0_b12_raw"] = body[12]
        out["c0_b16_raw"] = body[16]
    return out


# ---------- MQTT publisher ----------
class HAPublisher:
    def __init__(self, host, port, user, pw, prefix, node):
        import paho.mqtt.client as mqtt  # imported here so --raw needs no dep

        self.prefix = prefix
        self.node = node
        self.cli = mqtt.Client(client_id=f"aoboet-{node}")
        if user:
            self.cli.username_pw_set(user, pw)
        self.cli.will_set(f"{prefix}/{node}/availability", "offline", retain=True)
        self.cli.connect(host, port, keepalive=60)
        self.cli.loop_start()
        self._announced = False

    def _avail(self):
        return f"{self.prefix}/{self.node}/availability"

    def _state(self):
        return f"{self.prefix}/{self.node}/state"

    def announce(self, ncell):
        dev = {
            "identifiers": [f"aoboet_{self.node}"],
            "name": "AOBOET Battery",
            "manufacturer": "AOBOET",
            "model": "Uhome-LFP 16S",
        }
        base = {
            "avty_t": self._avail(),
            "stat_t": self._state(),
            "dev": dev,
        }

        def sensor(key, name, unit=None, dclass=None, tmpl=None, sclass="measurement"):
            cfg = dict(base)
            cfg.update(
                {
                    "name": name,
                    "uniq_id": f"aoboet_{self.node}_{key}",
                    "val_tpl": tmpl or f"{{{{ value_json.{key} }}}}",
                }
            )
            if unit:
                cfg["unit_of_meas"] = unit
            if dclass:
                cfg["dev_cla"] = dclass
            if sclass:
                cfg["stat_cla"] = sclass
            topic = f"{self.prefix}/sensor/aoboet_{self.node}/{key}/config"
            self.cli.publish(topic, json.dumps(cfg), retain=True)

        sensor("soc_pct", "Battery SOC", "%", "battery")
        sensor("pack_voltage_v", "Pack Voltage", "V", "voltage")
        sensor("cell_min_mv", "Cell Min", "mV", "voltage")
        sensor("cell_max_mv", "Cell Max", "mV", "voltage")
        sensor("cell_delta_mv", "Cell Delta", "mV", "voltage")
        sensor("cell_avg_mv", "Cell Avg", "mV", "voltage")
        sensor("current_a", "Current", "A", "current")
        for i in range(ncell):
            sensor(
                f"cell_{i+1}",
                f"Cell {i+1}",
                "mV",
                "voltage",
                tmpl=f"{{{{ value_json.cells_mv[{i}] }}}}",
            )
        self.cli.publish(self._avail(), "online", retain=True)
        self._announced = True

    def publish(self, data):
        if not self._announced:
            self.announce(data["cell_count"])
        self.cli.publish(self._state(), json.dumps(data), retain=False)


# ---------- main loop ----------
def serve(args):
    global TEMP_OFFSET
    TEMP_OFFSET = args.temp_offset
    pub = None
    if not args.raw:
        pub = HAPublisher(
            args.mqtt_host, args.mqtt_port, args.mqtt_user, args.mqtt_pass,
            args.mqtt_prefix, args.node,
        )
        print(f"[+] MQTT -> {args.mqtt_host}:{args.mqtt_port} prefix={args.mqtt_prefix}", file=sys.stderr)

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if False else socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.listen, args.port))
    srv.listen(1)
    print(f"[+] listening on {args.listen}:{args.port} (Socket B target)", file=sys.stderr)

    while True:
        conn, addr = srv.accept()
        print(f"[+] module connected from {addr[0]}", file=sys.stderr)
        conn.settimeout(120)
        framer = Framer()
        last = time.time()
        inv_extra = {}  # latest c0-derived fields, merged into c1 publishes
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                for frame in framer.feed(chunk):
                    t = frame[2]
                    if t == T_BATT:
                        d = decode_batt(frame)
                        if not d:
                            continue
                        d.update(inv_extra)  # attach current/temp from most recent c0
                        if args.raw:
                            print(
                                f"BATT soc={d['soc_pct']}% pack={d['pack_voltage_v']}V "
                                f"min={d['cell_min_mv']} max={d['cell_max_mv']} "
                                f"delta={d['cell_delta_mv']} "
                                f"I={d.get('current_a')}A "
                                f"cells={d['cells_mv']} field16={d['raw_field16']} tail=[{d['raw_tail']}]"
                            )
                        elif pub and time.time() - last >= args.interval:
                            pub.publish(d)
                            last = time.time()
                    elif t == T_INV:
                        di = decode_inv(frame)
                        if args.debug_c0:
                            body = frame[3 + ID_LEN : -2]
                            print(f"C0 bodylen={len(body)} hex={body.hex(' ')}", flush=True)
                        for k in ("current_a", "charging",
                                  "c0_b12_raw", "c0_b16_raw"):
                            if k in di:
                                inv_extra[k] = di[k]
                        if args.raw:
                            print(
                                f"INV  pack={di.get('pack_voltage_v')}V soc={di.get('soc_pct')}% "
                                f"I={di.get('current_a')}A charging={di.get('charging')}"
                            )
        except socket.timeout:
            print("[!] no data for 120s, dropping connection", file=sys.stderr)
        except Exception as e:
            print(f"[!] connection error: {e}", file=sys.stderr)
        finally:
            conn.close()
            print("[.] module disconnected, waiting for reconnect", file=sys.stderr)


def build_argparser():
    ap = argparse.ArgumentParser(description="AOBOET BMS passive collector (Socket B tap)")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9999, help="Socket B target port")
    ap.add_argument("--raw", action="store_true", help="print decoded frames, no MQTT")
    ap.add_argument("--interval", type=float, default=10.0, help="min seconds between MQTT publishes")
    ap.add_argument("--node", default="lfp1", help="node id used in MQTT topics/unique_ids")
    ap.add_argument("--mqtt-host", default="127.0.0.1")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-user", default=None)
    ap.add_argument("--mqtt-pass", default=None)
    ap.add_argument("--mqtt-prefix", default="homeassistant")
    ap.add_argument("--temp-offset", type=int, default=TEMP_OFFSET,
                    help="degrees C added to the raw c0 temp byte (default 22; "
                         "re-anchor as luxpower_C minus c0_b12_raw)")
    ap.add_argument("--debug-c0", action="store_true",
                    help="log every c0 frame's body length and hex (for field mapping)")
    return ap


if __name__ == "__main__":
    serve(build_argparser().parse_args())
