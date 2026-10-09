# Horus

**A custom network Intrusion Detection System (IDS) written in Python.**

Horus captures live traffic with Scapy, normalises every packet into a structured event, and runs it through a set of rule-based detectors. Alerts are shown in a real-time desktop dashboard and can be exported to CSV.

<img width="1079" height="725" alt="Horus_GUI" src="https://github.com/user-attachments/assets/79fb62d1-385c-454f-b24b-8e7baf0403a1" />

> **Status:** active personal project. Built to understand how network attacks look on the wire and how detection logic works, not as a replacement for Snort, Suricata or Zeek. See [Limitations](#limitations).

---

## Features

- **Live packet capture** on a selectable interface (Scapy `AsyncSniffer`, runs in its own thread).
- **Five detectors**, each validated against a real attack tool (see below).
- **IPv4 and IPv6 support** in the parser and in the detectors that don't depend on ARP.
- **Memory-bounded detection state:** a flood of spoofed source IPs cannot exhaust RAM.
- **YAML-configurable thresholds**, with strict validation: typos and nonsense values are rejected with a clear error instead of silently weakening detection.
- **Tkinter dashboard:** interface picker, start/stop, live alert table with severity colouring, counters (packets, alerts, high severity, uptime), CSV export.
- **Unit tests** that need no network, GUI or admin rights.

## Detections

| Detector | What it looks for | Severity | Validated with |
|---|---|---|---|
| **Port scan** | One source sending SYNs to many distinct TCP ports in a short window | MEDIUM | `nmap -sS -Pn -p 1-1000 <target>` |
| **UDP scan** | One source hitting many distinct UDP ports in a short window | MEDIUM | `nmap -sU -Pn -p 1-1000 <target>` |
| **SYN flood** | Many SYNs arriving at one *target* (dst IP + port), regardless of source | HIGH | `hping3 -S -p <port> --flood <target>` |
| **Brute force** | Many connection attempts from one source to a login port (SSH, FTP, Telnet, RDP) | HIGH | `hydra -l root -P rockyou.txt ssh://<target>` |
| **ARP spoofing** | An IP address suddenly claimed by a different MAC than the one first seen | HIGH | `arpspoof -i <iface> -t <target> <gateway>` |

Test setup: Horus runs on a Windows host; a Kali Linux VM (VirtualBox, bridged adapter) acts as the attacker.

A few design decisions worth noting:

- **SYN flood is keyed on the victim, not the attacker.** A flood with spoofed random sources still piles up on one `(dst_ip, dst_port)`, so it is detected where a per-source counter would miss it.
- **Only pure SYN packets (`flags == "S"`) count** for scan, flood and brute-force logic, so normal SYN-ACK replies don't inflate the counters.
- **ARP probes (sender `0.0.0.0`) are ignored**, since they are not real IP-to-MAC mappings and would cause false positives.
- **Every alert has a per-key cooldown**, so one attack produces one alert rather than thousands.

## Architecture

```
 network ──► sniffer ──► parser ──► detectors ──► alerts.emit() ──► subscribers
            (Scapy)    PacketEvent  (5 modules)                      ├─ console
                                                                     └─ GUI (via queue)
```

Detectors only know about `emit()`; they never know who is listening. Anything that wants alerts (the GUI today, a database or log writer tomorrow) registers a callback with `alerts.subscribe()`.

```
Horus/
├── main.py                  # launches the dashboard
├── config.yaml              # detector thresholds
├── requirements.txt
├── ids/
│   ├── config.py            # defaults + YAML loading + validation
│   ├── alerts.py            # Alert dataclass, emit(), subscribe()
│   ├── capture/
│   │   ├── parser.py        # Scapy packet -> PacketEvent
│   │   └── sniffer.py       # capture loop, hands events to detectors
│   ├── detection/
│   │   ├── window.py        # SlidingWindow + Cooldown (bounded memory)
│   │   ├── portscan.py
│   │   ├── udp_portscan.py
│   │   ├── syn_flood.py
│   │   ├── bruteforce.py
│   │   ├── arp_spoof.py
│   │   └── addr.py          # IPv4/IPv6 endpoint formatting
│   ├── gui/
│   │   └── app.py           # Tkinter dashboard
│   ├── scripts/             # helpers to enable/disable SSH for brute-force testing
│   └── tests/               # unit tests
└── misc/                    # logo and assets
```

### Components

**`capture/parser.py`:** translates raw Scapy packets into a `PacketEvent` dataclass. Timestamp and protocol are required; everything else (MACs, IPs, ports, TCP flags, ICMP type/code, DNS query, ARP fields) defaults to `None` and is filled in only when the packet has it. Detectors therefore work on one simple, uniform structure instead of poking at Scapy layers. Protocols recognised: TCP, UDP, ICMP, ARP (others are labelled `Unknown`).

**`capture/sniffer.py`:** owns capture. `packet_callback` runs for every packet, updates the packet counter, parses it and passes the event to every detector. It is wrapped in `try/except` so one malformed packet can't stop the capture. `create_sniffer()` returns an `AsyncSniffer` so the GUI can start and stop it from a button.

**`detection/window.py`:** the shared building blocks:
- `SlidingWindow` remembers recent events per key (for example per source IP), expires old ones, and answers `count()` / `distinct()` / `values()`. It sweeps idle keys periodically and enforces a hard cap on tracked keys (default 50,000), evicting the oldest.
- `Cooldown` guarantees `allow(key, now)` is true at most once per period per key, also with a hard cap.

**`alerts.py`:** `Alert` (kind, severity, source, message, timestamp) and `emit()`, which prints to the console and calls every subscriber. A failing subscriber is caught and reported so it can never interrupt detection.

**`config.py`:** built-in defaults are merged with `config.yaml`, so Horus still runs if the file is missing or lists only a few settings. Unknown sections or keys and invalid values raise a `ConfigError`. Setting `HORUS_CONFIG` points to a different file (the tests use this to run on defaults).

**`gui/app.py`:** Tkinter dashboard. Detectors run on the sniffing thread and only push alerts onto a queue; the GUI thread drains the queue every 200 ms and is the only code that touches widgets (Tkinter is not thread-safe). Per-poll and table-size caps stop an alert storm from freezing the window.

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

Choose an interface (or leave it on *Auto*), then press **Start monitoring**.

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

Sections: `port_scan`, `udp_scan`, `syn_flood`, `brute_force`, `arp_spoof`. These thresholds suit a small lab network; busy networks will need tuning.

### Tests

From the project root:

```bash
python -m unittest ids.tests.test_detectors ids.tests.test_parser -v
```

Detector tests build `PacketEvent`s by hand, so no capture, GUI or admin rights are needed. They cover the sliding window and cooldown (expiry, idle-key cleanup, memory caps) and each detector's positive and negative cases (below threshold, slow scans outside the window, IPv6, spoofed sources, ARP probes).

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
- **Detect only.** Horus raises alerts; it does not block anything.
- **No alert persistence yet.** Alerts live in the dashboard and CSV export.
- Thresholds were tuned on a small lab network, not production traffic.

## Roadmap

- [ ] SQLite storage for alerts, with search and filtering
- [ ] DNS anomaly detection (the parser already extracts DNS queries)
- [ ] Payload signature matching
- [ ] ICMP-based detections (sweeps, floods)
- [ ] Baseline/anomaly-based detection
- [ ] Optional IPS mode (active response)

## Tech stack

Python · Scapy · PyYAML · Tkinter · unittest

## Disclaimer

Horus is an educational project. Use the attack tools mentioned here only in environments you own or have explicit permission to test.