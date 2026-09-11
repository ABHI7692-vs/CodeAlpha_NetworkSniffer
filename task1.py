from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime

packet_count = 0


def analyze_packet(packet):
    global packet_count

    packet_count += 1
    time = datetime.now().strftime("%H:%M:%S")

    print("\n" + "-" * 55)
    print(f"Packet #{packet_count}    Time: {time}")
    print("-" * 55)

    # ARP packet
    if ARP in packet:
        print("Protocol    : ARP")
        print(f"Source IP   : {packet[ARP].psrc}")
        print(f"Destination : {packet[ARP].pdst}")
        return

    # IP packet
    if IP in packet:
        print(f"Source IP   : {packet[IP].src}")
        print(f"Destination : {packet[IP].dst}")
        print(f"Packet Size : {len(packet)} bytes")

        if TCP in packet:
            print("Protocol    : TCP")
            print(f"Source Port : {packet[TCP].sport}")
            print(f"Dest. Port  : {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol    : UDP")
            print(f"Source Port : {packet[UDP].sport}")
            print(f"Dest. Port  : {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol    : ICMP")
            print(f"ICMP Type   : {packet[ICMP].type}")

        else:
            print("Protocol    : Other")


def start_sniffer():
    print("=" * 55)
    print("             BASIC NETWORK SNIFFER")
    print("=" * 55)
    print("Capturing packets...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(prn=analyze_packet, store=False)

    except KeyboardInterrupt:
        print("\n\n" + "=" * 55)
        print("Sniffer stopped successfully.")
        print(f"Total packets captured: {packet_count}")
        print("=" * 55)


if __name__ == "__main__":
    start_sniffer()
