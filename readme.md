# Basic Network Sniffer

A lightweight CLI-based network packet sniffer written in Python using the Scapy library. This tool captures and analyzes live network traffic, extracting key protocol details and payloads.

## Features
- Captures live IPv4 packets on a specified network interface.
- Decodes layered protocols including TCP, UDP, and ICMP.
- Extracts and safely decodes raw packet payloads (first 100 bytes).
- Supports BPF (Berkeley Packet Filter) syntax for targeted sniffing.
- Graceful exit on `Ctrl+C` without breaking the terminal output.

## Prerequisites
- Python 3.x
- Scapy library (`pip install scapy`)
- Root/Administrator privileges (Required for capturing raw network sockets).

## Usage
Run the script with administrator privileges:

```bash
# General usage
sudo python3 sniffer.py -i <interface> -c <packet_count> -f <filter>

# Example: Capture 5 TCP packets on eth0
sudo python3 sniffer.py -i eth0 -c 5 -f "tcp"