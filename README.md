# Horus

**A custom network Intrusion Detection System (IDS) written in Python.**

Horus captures live traffic with Scapy, normalises every packet into a structured event, and runs it through a set of rule-based detectors. Alerts are shown in a real-time desktop dashboard, saved to a local SQLite database, and can be exported to CSV.

<img width="1077" height="725" alt="Horus_Dashboard" src="https://github.com/user-attachments/assets/779b621c-ee3d-48d1-b31d-e4e880502f69" />

> **Status: v1.0 (stable).** The feature set is complete and tested, and the project is now in maintenance mode: bug fixes only for the moment. Built to understand how network attacks look on the wire and how detection logic works, not as a replacement for Snort, Suricata or Zeek. See [Limitations](#limitations) and the [Roadmap](#roadmap).

---

## Features

- **Live packet capture** on a selectable interface (Scapy `AsyncSniffer`, runs in its own thread).
- **Seven detectors**, each validated against a real attack tool (see below).
- **IPv4 and IPv6 support** in the parser and in the detectors that don't depend on ARP.
- **Memory-bounded detection state:** a flood of spoofed source IPs cannot exhaust RAM.
- **YAML-configurable thresholds**, with strict validation: typos and nonsense values are rejected at startup with a clear message instead of silently weakening detection.
- **Alert storage:** every alert is written to `horus.db` (SQLite) by a background thread, so a slow disk never delays packet processing. Each Start/Stop is recorded as a session.
- **Tkinter dashboard:** interface picker, start/stop, live alert table with severity colouring, counters (packets, alerts, high severity, uptime) and CSV export.
- **CSV export of the full history:** the file contains every alert saved since Horus was opened (or since the last **Clear**), including those that already scrolled out of the table.
- **Fails loudly, not silently:** the dashboard warns when no traffic is seen for 30 seconds, raises a HIGH alert if the capture thread dies, and reports it if the alert database stops, falls behind or refuses alerts.
- **Fault isolation:** one broken detector (or one malformed packet) cannot blind the others; failures are counted and rate-limited in the console.
- **Clean sessions:** every Start wipes what the detectors learned (counters, cooldowns, the ARP table), and packets still in flight from a stopped capture can never leak into the next session.
- **Unit tests** that need no network, GUI or admin rights.

## Detections

| Detector | What it looks for | Severity | Validated with |
|---|---|---|---|
| **Port scan** | One source sending SYNs to many distinct TCP ports in a short window | MEDIUM | `nmap -sS -Pn -p 1-1000 <target>` |
| **UDP scan** | One source hitting many distinct UDP ports in a short window | MEDIUM | `nmap -sU -Pn -p 1-1000 <target>` |
| **SYN flood** | Many SYNs arriving at one *target* (dst IP + port), regardless of source | HIGH | `hping3 -S -p <port> --flood <target>` |
| **ICMP flood** | Many ICMP echo requests (pings) arriving at one *target*, regardless of source | HIGH | `hping3 --icmp --flood <target>` |
| **Unusual ICMP** | ICMP timestamp, information or address-mask requests: rarely legitimate today, and used to probe hosts | LOW | `hping3 --icmp --icmptype 13 -c 3 <target>` |
| **Brute force** | Many connection attempts from one source to a login port (SSH, FTP, Telnet, RDP) | HIGH | `hydra -l root -P rockyou.txt ssh://<target>` |
| **ARP spoofing** | An IP address suddenly claimed by a different MAC than the one first seen | HIGH | `arpspoof -i <iface> -t <target> <gateway>` |

Test setup: Horus runs on a Windows host; a Kali Linux VM (VirtualBox, bridged adapter) acts as the attacker.

A few design decisions worth noting:

- **SYN flood is keyed on the victim, not the attacker.** A flood with spoofed random sources still piles up on one `(dst_ip, dst_port)`, so it is detected where a per-source counter would miss it.
- **Only connection attempts count** for scan, flood and brute-force logic: a packet with the SYN flag set and the ACK flag clear. Other flags (ECE, CWR, PSH, URG, FIN) are ignored, so the ECN-setup SYNs that macOS/iOS send, and crafted packets that add extra flags to dodge an exact `== "S"` match, are still caught, while normal SYN-ACK replies never inflate the counters. In the same way, the ICMP flood detector counts only echo *requests* (type 8), never replies.
- **ARP probes (sender `0.0.0.0`) are ignored**, since they are not real IP-to-MAC mappings and would cause false positives.
- **Unusual ICMP is deliberately LOW severity.** A single odd packet is a hint that someone is probing, not proof of an attack. It watches requests only (types 13, 15, 17), never the replies, so Horus never alerts about its own host answering.
- **Every alert has a per-key cooldown**, so one attack produces one alert rather than thousands.

## Architecture

```
 network ──► sniffer ──► parser ──► detectors ──► alerts.emit() ──► subscribers
            (Scapy)    PacketEvent  (7 modules)                      ├─ console
                                                                     ├─ GUI (via queue)
                                                                     └─ SQLite (via queue + writer thread)
```

Detectors only know about `emit()`; they never know who is listening. Anything that wants alerts (the GUI and the SQLite store today, a log writer tomorrow) registers a callback with `alerts.subscribe()`.

```
Horus/
├── main.py                  # launches the dashboard (validates config.yaml first)
├── config.yaml              # detector thresholds
├── requirements.txt
├── ids/
│   ├── config.py            # defaults + YAML loading + validation
│   ├── alerts.py            # Alert dataclass, emit(), subscribe()
│   ├── capture/
│   │   ├── parser.py        # Scapy packet -> PacketEvent
│   │   └── sniffer.py       # capture, detector hand-off, session start/stop safety
│   ├── detection/
│   │   ├── window.py        # SlidingWindow + Cooldown (bounded memory)
│   │   ├── portscan.py
│   │   ├── udp_portscan.py
│   │   ├── syn_flood.py
│   │   ├── icmp_flood.py
│   │   ├── icmp_unusual.py
│   │   ├── bruteforce.py
│   │   ├── arp_spoof.py
│   │   ├── tcpflags.py      # "SYN set, ACK clear" check shared by TCP detectors
│   │   └── addr.py          # IPv4/IPv6 endpoint formatting
│   ├── storage/
│   │   ├── db.py            # SQLite alert store (background writer thread)
│   │   └── export.py        # CSV export (reads the full history from the database)
│   ├── gui/
│   │   └── app.py           # Tkinter dashboard
│   ├── scripts/             # SSH enable/disable helpers, sniff_demo.py (manual)
│   └── tests/               # unit tests
└── misc/                    # logo and assets
```

### Components

**`capture/parser.py`:** translates raw Scapy packets into a `PacketEvent` dataclass. Timestamp and protocol are required; everything else (MACs, IPs, ports, TCP flags as a bitmask, ICMP type/code, DNS query, ARP fields) defaults to `None` and is filled in only when the packet has it. Detectors therefore work on one simple, uniform structure instead of poking at Scapy layers. Protocols recognised: TCP, UDP, ICMP, ARP (others are labelled `Unknown`).

**`capture/sniffer.py`:** owns capture. `packet_callback` runs for every packet, updates the packet counter, parses it and passes the event to every detector. It is wrapped in `try/except` so one malformed packet can't stop the capture, and each detector runs in its own `try/except` so a faulty one can't stop the others. `create_sniffer()` returns an `AsyncSniffer` so the GUI can start and stop it from a button.

Stopping a Scapy sniffer is asynchronous, so the module also protects session boundaries: every sniffer gets a token, `deactivate_sniffer()` (Stop) invalidates it, and `begin_session()` (Start) zeroes the counters and resets every detector under the same lock that guards packet processing. Packets that a dying capture thread still delivers are ignored instead of leaking into the next session.

**`detection/window.py`:** the shared building blocks:
- `SlidingWindow` remembers recent events per key (for example per source IP), expires old ones, and answers `count()` / `distinct()` / `values()` / `top()`. It sweeps idle keys periodically and enforces a hard cap on tracked keys (default 50,000), evicting the oldest.
- `Cooldown` guarantees `allow(key, now)` is true at most once per period per key, also with a hard cap.

**`alerts.py`:** `Alert` (kind, severity, source, message, timestamp, plus optional target, destination port and detector-specific details) and `emit()`, which prints to the console and calls every subscriber. A failing subscriber is caught and reported so it can never interrupt detection.

**`storage/db.py`:** SQLite storage for alerts. `AlertStore` is one per monitoring session (Start to Stop): the sniffing thread only puts each alert on a queue, and a dedicated writer thread owns the database connection and inserts in batches, so a slow disk can never delay packet processing. A single malformed alert is skipped and counted rather than taking down the batch. Alerts are stored with UTC timestamps in `horus.db`, with a `sessions` table recording the interface and settings used for each run. `recent_alerts()` reads them back, newest first, optionally filtered by kind, source or severity; `alerts_since()` returns the full history, oldest first, for the export.

**`storage/export.py`:** writes alerts to CSV (time, severity, type, source, target, port, message, details as JSON). The dashboard table only keeps the newest 2000 alerts, so the export reads the database instead. It falls back to what the table shows if the database failed, lost alerts or can't be read, and says so in the status bar.

**`config.py`:** built-in defaults are merged with `config.yaml`, so Horus still runs if the file is missing or lists only a few settings. Unknown sections or keys and invalid values raise a `ConfigError`, which `main.py` shows in a message box before the dashboard opens. Setting `HORUS_CONFIG` points to a different file (the tests use this to run on defaults).

**`gui/app.py`:** Tkinter dashboard. Detectors run on the sniffing thread and only push alerts onto a queue; the GUI thread drains the queue every 200 ms and is the only code that touches widgets (Tkinter is not thread-safe). Per-poll and table-size caps stop an alert storm from freezing the window. A watchdog polls the capture thread and the database writer and surfaces problems as alerts and status messages.

## Getting started

### Requirements

- Python 3.11+
- **Windows:** [Npcap](https://npcap.com/) installed
- **Linux/macOS:** libpcap (usually already present)
- Packet capture needs elevated privileges: run as Administrator (Windows) or with `sudo` (Linux/macOS)

### Install and run

```bash
git clone https://github.com/<your-username>/Horus.git
cd Horus
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

python main.py
```

Choose an interface (or leave it on *Auto*), then press **Start monitoring**. Use **Export CSV** to save the alerts and **Clear** to empty the table and start a fresh export.

### Configuration

Edit `config.yaml`. Any setting you leave out uses the built-in default.

```yaml
port_scan:
  threshold: 15          # distinct TCP ports from one source...
  window_seconds: 5      # ...within this many seconds
  cooldown_seconds: 30   # minimum gap between repeat alerts for the same source

brute_force:
  threshold: 10
  window_seconds: 10
  cooldown_seconds: 30
  ports: [22, 21, 23, 3389]   # SSH, FTP, Telnet, RDP
```

Sections: `port_scan`, `udp_scan`, `syn_flood`, `icmp_flood`, `icmp_unusual`, `brute_force`, `arp_spoof`. These thresholds suit a small lab network; busy networks will need tuning. Changes take effect the next time Horus is started.

### Tests

From the project root:

```bash
python -m unittest discover -s ids/tests -t . -v
```

No capture, GUI or admin rights are needed (the GUI tests replace Tkinter with a stand-in). Detector tests build `PacketEvent`s by hand and cover the sliding window and cooldown (expiry, idle-key cleanup, memory caps) and each detector's positive and negative cases (below threshold, slow scans outside the window, IPv6, spoofed sources, TCP flag variants, ARP probes). The remaining suites cover:

- the parser, with real Scapy packets (IPv4, IPv6, flags, lengths)
- the sniffer: detector isolation, session resets, and the Start/Stop race
- SQLite storage: bad alerts, queue limits, a dead writer, `flush()`, history queries
- config validation and the startup error path in `main.py`
- CSV export, including the full-history behaviour and its fallbacks

### Reproducing the attack tests

1. Run Horus on the target machine and start monitoring.
2. From the attacker (e.g. Kali), run the command from the [Detections](#detections) table.
3. For brute force, enable SSH on the Windows target with `ids/scripts/enable_ssh_test.ps1`, and **run `disable_ssh_test.ps1` when finished**.

Only test on machines and networks you own or are authorised to test.

## Limitations

Stated plainly, so the scope is clear:

- **Rule/threshold-based only.** There is no payload inspection and no anomaly detection or machine learning, so it won't catch attacks that stay under the thresholds (slow scans, for example).
- **Brute-force detection is connection-rate based.** It counts SYNs to login ports, not failed authentications. Tools that reuse one connection can slip past it, and a legitimate script opening many connections can trigger it.
- **ARP spoofing detection is first-seen-wins.** A legitimate MAC change (new NIC, failover, DHCP churn) will alert, and an attack that happens before Horus has learned the mapping will not.
- **ICMP detection is IPv4 only.** The parser does not recognise ICMPv6 yet, so an IPv6 ping flood is not detected. Ping *sweeps* are not detected either.
- **The unusual-ICMP detector is informational.** Some network tools do send timestamp requests, so a LOW alert is a hint to look, not a verdict.
- **Detect only.** Horus raises alerts; it does not block anything.
- **No way to browse saved alerts in the GUI yet.** Alerts are stored in `horus.db`, but the dashboard only shows the current run (the newest 2000 alerts). The full history can be reached through **Export CSV** or by opening the database directly.
- **No retention policy.** `horus.db` grows for as long as Horus runs; delete the file to start over.
- **Developed and tested on Windows.** It should run on Linux/macOS, but that is less tested.
- Thresholds were tuned on a small lab network, not production traffic.

## Roadmap

Horus v1.0 is feature-complete for its original scope. Possible future work:

- [x] SQLite storage for alerts
- [x] ICMP flood detection
- [x] CSV export of the full alert history
- [ ] Alert history view in the GUI, with search and filtering
- [ ] DNS anomaly detection (the parser already extracts DNS queries)
- [ ] ICMPv6 / IPv6 neighbour discovery (NDP spoofing) support
- [ ] Payload signature matching
- [ ] Sweep detection (ICMP and ARP)
- [ ] Baseline/anomaly-based detection
- [ ] Optional IPS mode (active response)

## Tech stack

Python · Scapy · PyYAML · Tkinter · SQLite · unittest

## Disclaimer

Horus is an educational project. Use the attack tools mentioned here only in environments you own or have explicit permission to test.
