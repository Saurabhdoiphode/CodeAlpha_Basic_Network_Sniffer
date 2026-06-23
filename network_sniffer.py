import argparse

from scapy.all import ICMP, IP, Raw, TCP, UDP, sniff


def cb(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    proto = ip_layer.proto

    if pkt.haslayer(TCP):
        proto = "TCP"
    elif pkt.haslayer(UDP):
        proto = "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    print(f"[{proto}] {src} ===> {dst} | Len: {len(pkt)}")

    if pkt.haslayer(Raw):
        payload = pkt[Raw].load[:60].decode(errors="replace")
        print(f"Payload: {payload}")


def parse_args():
    parser = argparse.ArgumentParser(description="Simple CLI network sniffer")
    parser.add_argument("-i", "--interface", dest="iface", required=True, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 means unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        sniff(
            iface=args.iface,
            prn=cb,
            count=args.count,
            filter=args.filter or None,
            store=0,
        )
    except KeyboardInterrupt:
        print("\nSniffing stopped.")


if __name__ == "__main__":
    main()
