from scapy.all import Ether, IP, TCP, Raw, wrpcap
from pcap_analyzer.pcap_stats import PcapAnalyzer
import os
import shutil

def create_http_file_pcap(filename):
    pkts = []
    
    # Simulate HTTP connection transferring an image
    # HTTP Response with an image
    ip_src = "10.0.0.1"
    ip_dst = "10.0.0.2"
    sport = 80
    dport = 54321
    
    # Fake PNG content
    png_header = b"\x89PNG\r\n\x1a\n"
    png_data = b"FAKE_IMAGE_DATA_FLAG_INSIDE"
    
    http_headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: image/png\r\n"
        b"Content-Disposition: attachment; filename=\"secret_flag.png\"\r\n"
        b"Content-Length: 35\r\n"
        b"\r\n"
    )
    
    payload = http_headers + png_header + png_data
    
    # Packet 1 matches typical interaction
    p1 = Ether()/IP(src=ip_src, dst=ip_dst)/TCP(sport=sport, dport=dport, seq=1000, flags="PA")/Raw(load=payload)
    
    pkts.append(p1)
    
    wrpcap(filename, pkts)
    print(f"Created {filename}")

def verify():
    filename = "test_phase3.pcap"
    output_dir = "extracted_files"
    
    # cleanup first
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        
    create_http_file_pcap(filename)
    
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        extracted = stats.get('extracted_files', [])
        found_file = False
        
        print("\nExtracted files:")
        for f in extracted:
            print(f)
            if f['filename'] == "secret_flag.png":
                found_file = True
                # verify content
                with open(f['path'], 'rb') as extracted_f:
                    content = extracted_f.read()
                    if b"FAKE_IMAGE_DATA" in content:
                        print("[SUCCESS] Content verified match!")
                    else:
                        print("[FAILURE] Content mismatch!")
                        found_file = False
                
        if found_file:
            print("\n[SUCCESS] File extraction verified!")
        else:
            print("\n[FAILURE] File extracted failed!")
            
    finally:
        if os.path.exists(filename):
            os.remove(filename)
        # We can leave the extracted files for user to see, or clean up:
        # shutil.rmtree(output_dir)

if __name__ == "__main__":
    verify()
