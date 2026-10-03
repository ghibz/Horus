# Horus
Horus - Custom Made Intrusion Detection System (IDS)

<img width="1079" height="725" alt="Horus_GUI" src="https://github.com/user-attachments/assets/79fb62d1-385c-454f-b24b-8e7baf0403a1" />

_____________________________________________________________________________________

Horus is a personal project made due to desire of combining both networking and cyber-security in a project that could help me better understand some topics in these fields, but also get more familiar with Python and coding in general.

It is an on-going project, as of now I would like to add more detection capabilities, an SQL database of alerts, and in the future maybe even IPS capabilities.

_____________________________________________________________________________________

Structure of code:
main.py
ids
 > capture
   > __init__.py
   > parser.py
   > sniffer.py
 > detection
   > __init__.py
   > arp_spoof.py
   > portscan.py
   > syn_flood.py
   > window.py
 > gui
   > __init__.py
   > app.py
 > tests
   > __init__.py
   > test_detectors.py
 > __init__.py
 > alerts.py

_____________________________________________________________________________________

** parser.py **

This part of the code is a way of translating scapy (Python package used to sniff packets) raw packets into a format that would be much easier to read and actually rely on. I used a 'PacketEvent' dataclass, which holds every field that a packet type might produce, with the timestamps and protocol fields being REQUIRED, and everything else, things such as MAC address, IP address, ICMP type, etc, to be set to None by default, and get filled in later if needed.

extract_general_fields is a function which pulls all the general stuff which every packet has (timestamp, MAC address, IP version, length)

detect_protocol, as the name suggests, is a function which looks at the scapy layers and makes a decision of what the protocol is, as of now only TCP, UDP, ICMP, ARP or Unknown are the possible options. Each of these four protocols has an extractor functions which will pull the fields specific to that protocol.

parse_packet puts is all together, detects protocol, runs the general extraction, runs the specific extraction, merges both of these and constructs the 'PacketEvent'.

_____________________________________________________________________________________

** sniffer.py **

The sniffer owns actual packet capture. The packet_callback function runs on every captured packet, and increments the 'packets' counter (for the GUI display), parses the packet, and hands the resulting event to every detector via the handle_packet_event, wrapped in a try/except so that a malformed packet won't kill the entire loop.

list_interfaces gives the GUI a list of network interfaces to choose from.

create_sniffer builds an 'AsyncSniffer' - a GUI-enabling change made from before, which runs in its own thread and is exposed to .start() and .stop(), so that the GUI can be controlled.

_____________________________________________________________________________________

** alerts.py **

'Alert' is a dataclass bundling kind, severity, source, message and an auto-generated timestamp. The emit() function that every detector calls to raise an alert. It will then build the 'Alert', printing it to the console everytime so we do not miss anything, then calls every function registered via subscribe().

_____________________________________________________________________________________

** window.py **
