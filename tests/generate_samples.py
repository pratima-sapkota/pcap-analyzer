from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import base64
import os

def safe_wrpcap(filename, pkts):
    output_dir = os.path.dirname(filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    wrpcap(filename, pkts)
    print(f"Created {filename}")

def create_mixed_pcap(filename):
    """
    Creates a pcap with:
    1. UDP packet with a flag (single packet)
    2. TCP stream with plain text split flag
    3. TCP stream with base64 split flag
    """
    pkts = []
    
    # 1. UDP Packet
    # Use non-standard port to avoid auto-decoding (e.g. DNS on 53)
    pkts.append(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=5555, dport=1234)/Raw(load="UDP packet with flag{udp_flag} inside"))
    
    # 2. TCP Split Plain
    # "flag{tcp" + "_plain}"
    p1 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1001, dport=80, seq=100, flags="PA")/Raw(load="data before flag{tcp")
    p2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1001, dport=80, seq=116, flags="PA")/Raw(load="_plain} data after")
    pkts.append(p1)
    pkts.append(p2)
    
    # 3. TCP Split Base64
    # flag{tcp_b64} -> ZmxhZ3t0Y3BfYjY0fQ==
    # Split: "ZmxhZ3t0Y" + "3BfYjY0fQ=="
    # Note: Analyzer currently expects pure base64 for decoding, so no extra text.
    p3 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1002, dport=80, seq=200, flags="PA")/Raw(load="ZmxhZ3t0Y")
    p4 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1002, dport=80, seq=209, flags="PA")/Raw(load="3BfYjY0fQ==")
    pkts.append(p3)
    pkts.append(p4)
    
    safe_wrpcap(filename, pkts)

def create_ooo_pcap(filename):
    """
    Creates a pcap with out-of-order TCP packets.
    Reassembly should handle this.
    flag{order_is_here}
    P1: "flag{order" (seq 100)
    P2: "_is"        (seq 110)
    P3: "_here}"     (seq 113)
    
    Order in pcap: P1, P3, P2
    """
    pkts = []
    sport = 2001
    
    p1 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=100, flags="PA")/Raw(load="flag{order")
    p2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=110, flags="PA")/Raw(load="_is")
    p3 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=113, flags="PA")/Raw(load="_here}")
    
    pkts.append(p1)
    pkts.append(p3) # Out of order
    pkts.append(p2)
    
    safe_wrpcap(filename, pkts)

def create_multi_match_pcap(filename):
    """
    Creates a pcap with multiple flags in one stream.
    """
    pkts = []
    sport = 3001
    
    # "Start flag{one} Middle flag{two} End"
    payload = "Start flag{one} Middle flag{two} End"
    # Split it
    part1 = payload[:10] # "Start flag"
    part2 = payload[10:20] # "{one} Midd"
    part3 = payload[20:] # "le flag{two} End"
    
    p1 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=100, flags="PA")/Raw(load=part1)
    p2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=110, flags="PA")/Raw(load=part2)
    p3 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=120, flags="PA")/Raw(load=part3)
    
    pkts.append(p1)
    pkts.append(p2)
    pkts.append(p3)
    
    safe_wrpcap(filename, pkts)

def create_pico_pcap(filename):
    """
    Creates a pcap with a picoCTF formatted flag.
    """
    pkts = []
    sport = 4001
    
    # picoCTF{this_is_a_pico_flag}
    # Split across two packets
    p1 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=100, flags="PA")/Raw(load="This is unexpected: picoCTF{th")
    p2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=80, seq=130, flags="PA")/Raw(load="is_is_a_pico_flag}")
    
    pkts.append(p1)
    pkts.append(p2)
    
    safe_wrpcap(filename, pkts)

if __name__ == "__main__":
    # stored in data/ directory relative to project root (assuming run from root)
    # or just use explicit path
    DATA_DIR = "data"
    
    create_mixed_pcap(os.path.join(DATA_DIR, "sample_mixed.pcap"))
    create_ooo_pcap(os.path.join(DATA_DIR, "sample_ooo.pcap"))
    create_multi_match_pcap(os.path.join(DATA_DIR, "sample_multi_match.pcap"))
    create_pico_pcap(os.path.join(DATA_DIR, "sample_pico.pcap"))
