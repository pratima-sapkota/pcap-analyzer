from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import base64
import codecs
from pcap_analyzer.pcap_stats import PcapAnalyzer
import os

def create_test_pcap(filename):
    pkts = []
    
    # 1. Plain flag
    pkts.append(Ether()/IP(dst="1.2.3.4")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\nflag{plain_text_flag}"))
    
    # 2. Base64 flag
    # flag{b64_flag} -> ZmxhZ3tiNjRfZmxhZ30=
    b64_payload = base64.b64encode(b"flag{b64_flag}").decode()
    pkts.append(Ether()/IP(dst="1.2.3.4")/TCP(dport=9999)/Raw(load=b64_payload))
    
    # 3. Rot13 flag
    # flag{rot13_flag} -> synt{ebg13_synt}
    rot13_payload = codecs.encode("flag{rot13_flag}", "rot_13")
    pkts.append(Ether()/IP(dst="1.2.3.4")/TCP(dport=443)/Raw(load=f"Some data {rot13_payload}"))
    
    wrpcap(filename, pkts)
    print(f"Created {filename}")

def verify():
    filename = "test_phase1.pcap"
    create_test_pcap(filename)
    
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        flags = stats.get('flags', [])
        found_plain = False
        found_b64 = False
        found_rot13 = False
        
        print("\nFound flags:")
        for f in flags:
            print(f)
            if "flag{plain_text_flag}" in f['match']: found_plain = True
            if "flag{b64_flag}" in f['match']: found_b64 = True
            if "flag{rot13_flag}" in f['match']: found_rot13 = True
            
        if found_plain and found_b64 and found_rot13:
            print("\n[SUCCESS] All flags found!")
        else:
            print("\n[FAILURE] Missing flags!")
            if not found_plain: print("- Missing plain flag")
            if not found_b64: print("- Missing base64 flag")
            if not found_rot13: print("- Missing rot13 flag")
            
    finally:
        if os.path.exists(filename):
            os.remove(filename)

if __name__ == "__main__":
    verify()
