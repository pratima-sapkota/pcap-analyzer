from scapy.all import Ether, IP, TCP, Raw, wrpcap
from pcap_analyzer.pcap_stats import PcapAnalyzer
import os

def create_split_flag_pcap(filename):
    pkts = []
    
    # Connection 1: Split plain text flag
    # "flag{spl" + "it_flag}"
    ip_src = "192.168.1.100"
    ip_dst = "192.168.1.200"
    sport = 12345
    dport = 80
    
    # Handshake (simplified, just data packets needed for reassembly really usually)
    # Packet 1
    p1 = Ether()/IP(src=ip_src, dst=ip_dst)/TCP(sport=sport, dport=dport, seq=1000, flags="PA")/Raw(load="flag{spl")
    # Packet 2
    p2 = Ether()/IP(src=ip_src, dst=ip_dst)/TCP(sport=sport, dport=dport, seq=1009, flags="PA")/Raw(load="it_flag}")
    
    pkts.append(p1)
    pkts.append(p2)
    
    wrpcap(filename, pkts)
    print(f"Created {filename}")

def verify():
    filename = "test_phase2.pcap"
    create_split_flag_pcap(filename)
    
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        stream_flags = stats.get('stream_flags', [])
        found_split = False
        
        print("\nFound stream flags:")
        for f in stream_flags:
            print(f)
            if "flag{split_flag}" in f['match']:
                found_split = True
                
        if found_split:
            print("\n[SUCCESS] Split flag found in stream!")
        else:
            print("\n[FAILURE] Split flag NOT found!")
            
    finally:
        if os.path.exists(filename):
            os.remove(filename)

if __name__ == "__main__":
    verify()
