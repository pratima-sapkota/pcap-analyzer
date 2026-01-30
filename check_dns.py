
from scapy.all import rdpcap, DNS, DNSQR

def check_dns(pcap_path):
    print(f"Checking DNS in {pcap_path}...")
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error: {e}")
        return

    for pkt in pkts:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            print(f"DNS Query: {query}")

if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        check_dns(f)
