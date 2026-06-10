from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

print("=" * 60)
print("       CodeAlpha - Basic Network Sniffer")
print("          Developed by: Saad")
print("=" * 60)
print()

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "OTHER"
            src_port = "-"
            dst_port = "-"
        payload = ""
        if Raw in packet:
            payload = packet[Raw].load[:30]
        print(f"[{timestamp}] {protocol}")
        print(f"  Source     : {src_ip}:{src_port}")
        print(f"  Destination: {dst_ip}:{dst_port}")
        if payload:
            print(f"  Payload    : {payload}")
        print("-" * 50)

try:
    print("[*] Sniffing started... Press Ctrl+C to stop\n")
    sniff(prn=packet_callback, store=False, count=100)
except KeyboardInterrupt:
    print("\n[!] Sniffer stopped by user.")
