
from scapy.all import rdpcap, TCP, UDP
try:
    from scapy.layers.tls.all import TLS
except ImportError:
    TLS = None
import sys
from collections import Counter

def analyze_protocols(pcap_path):
    print(f"Analyzing {pcap_path}...")
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    layers = Counter()
    tls_count = 0
    
    for pkt in pkts:
        l = pkt
        while l:
            layers[l.name] += 1
            if TLS and l.name == 'TLS':
                tls_count += 1
            l = l.payload
            
    print(f"  Layers found: {dict(layers)}")
    print(f"  TLS/SSL Packets: {tls_count}")

    # Check for common encrypted ports if Scapy doesn't dissect TLS automatically well without config
    encrypted_ports = 0
    for pkt in pkts:
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport == 443 or dport == 443:
                encrypted_ports += 1
    print(f"  Packets on port 443 (HTTPS): {encrypted_ports}")

if __name__ == "__main__":
    for f in sys.argv[1:]:
        analyze_protocols(f)
