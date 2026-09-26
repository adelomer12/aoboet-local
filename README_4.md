# aoboet-local

Read an **AOBOET Uhome-LFP** battery locally — no vendor app, no cloud account.

The AOBOET battery ships a **USR-WIFI232**-family serial-to-WiFi module that
tunnels the BMS serial stream to a vendor cloud. This project talks to the
module directly instead: it provisions WiFi, reads/writes the module
configuration over the USR network-AT interface, and decodes the BMS frame
format into Home Assistant sensors over MQTT — entirely on your LAN.

Built after the AOBOET app's registration step failed and support went
unanswered. It has been validated against a **Luxpower SNA5000** inverter's
Modbus readings for the same battery (pack voltage, SOC and temperature all
match).

## Scripts

| Script | What it does |
| --- | --- |
| `aoboet_wifi_provision.py` | Onboard the module's WiFi without the app, using the USR "fast access" UDP protocol (broadcast to :49000, replies on :26000). |
| `usr_at_query.py` | Read the module's real configuration over the network-AT interface (UDP 48899). Also a **guarded** `--set-socketb` that repoints the module's second socket to your collector and nothing else. |
| `aoboet_collector.py` | TCP listener that reassembles the BMS stream, validates each frame's CRC, decodes it, and publishes to Home Assistant via MQTT autodiscovery. Receive-only by design — it never transmits toward the BMS. |

## How it works

The module can mirror its serial stream to a second TCP socket ("Socket B").
Point Socket B at a host running `aoboet_collector.py` and you get a live copy
of everything the BMS emits, while the cloud link (Socket A) keeps running
untouched — or is blocked at your firewall if you want it fully local.

### Frame format (reverse-engineered)

```
AA 55 | TYPE(1) | DEVICE-ID(19 ASCII) | BODY | CRC-16/ARC (2 bytes, big-endian)
```

- **CRC-16/ARC**: poly `0x8005`, init `0x0000`, refin, refout, xorout `0x0000`,
  computed over everything from `AA 55` through the last body byte.
- Two logical nodes share one serial line: an ID containing `...B...` is the
  **battery/BMS** node, `...S...` is the **inverter/system** node.

| Type | Direction | Meaning |
| --- | --- | --- |
| `0xC1` | device→cloud | Battery: `28 10` prefix, 16× uint16-BE cell mV, SOC, other fields being mapped |
| `0xC0` | device→cloud | Inverter/system: pack voltage, SOC, current (provisional), temperature |
| `0xA2` / `0xB1` / `0xD0` | both | Heartbeat / clock — ignored |

## Quick start

Discover and read the module's config (read-only):

```bash
python3 usr_at_query.py <MODULE_IP>
```

Point the module's Socket B at your collector (the only write this tool makes):

```bash
python3 usr_at_query.py <MODULE_IP> --set-socketb <COLLECTOR_IP>:9999
```

Watch decoded frames with no MQTT:

```bash
python3 aoboet_collector.py --raw
```

Run as a Home Assistant MQTT service (Docker):

```bash
docker run -d --name aoboet --restart unless-stopped --network host \
    -v $PWD:/app -w /app python:3-alpine sh -c \
    "pip install --quiet paho-mqtt && python aoboet_collector.py \
       --mqtt-host <HA_IP> --mqtt-user <USER> --mqtt-pass <PASS>"
```

Home Assistant autodiscovers an "AOBOET Battery" device with SOC, pack voltage,
cell min/max/delta/avg, per-cell voltages, and (provisional) current and
temperature.

## Status

- **Confirmed:** per-cell voltages, cell count, SOC, pack voltage.
- **Provisional:** current magnitude (÷10), current sign, temperature encoding.
- **Not yet decoded:** cycle count, SOH.

## Security

The module's config interfaces are **unauthenticated** (a public search
password on UDP 48899, and a web UI). Keep the module on an isolated IoT VLAN,
allow only the collector's return path plus management access, change the
AT search password (`AT+ASWD`) and the web login, and — if you want it fully
local — block the module's route to the vendor cloud at your router.

## Disclaimer

Reverse-engineered from a personally owned device for interoperability. Not
affiliated with, authorized by, or endorsed by AOBOET or USR-IOT. Provided
as-is, with no warranty. You are responsible for how you use it on your own
equipment and network.

## License

MIT — see [LICENSE](LICENSE).
