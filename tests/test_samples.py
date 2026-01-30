from pcap_analyzer.pcap_stats import PcapAnalyzer
import os
import sys

# Add tests directory to path to import generate_samples
sys.path.append(os.path.dirname(__file__))
from generate_samples import create_mixed_pcap, create_ooo_pcap, create_multi_match_pcap, create_pico_pcap

def test_mixed_protocols():
    filename = "data/sample_mixed.pcap"
    create_mixed_pcap(filename)
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        # Check UDP flag (likely in single packet flags)
        flags = stats.get('flags', [])
        udp_matches = [f['match'] for f in flags if "flag{udp_flag}" in f['match']]
        udp_found = bool(udp_matches)
        
        # Check TCP Stream flags (reassembled)
        stream_flags = stats.get('stream_flags', [])
        tcp_plain_matches = [f['match'] for f in stream_flags if "flag{tcp_plain}" in f['match']]
        tcp_b64_matches = [f['match'] for f in stream_flags if "flag{tcp_b64}" in f['match']]
        
        tcp_plain_found = bool(tcp_plain_matches)
        tcp_b64_found = bool(tcp_b64_matches)
        
        all_matches = udp_matches + tcp_plain_matches + tcp_b64_matches
        if all_matches:
            print(f"  Found flags: {all_matches}")
        
        if udp_found and tcp_plain_found and tcp_b64_found:
            print("[SUCCESS] test_mixed_protocols: All flags found.")
        else:
            print("[FAILURE] test_mixed_protocols: Missing flags.")
            if not udp_found: print(" - Missing UDP flag (expected in single packet flags)")
            if not tcp_plain_found: print(" - Missing TCP plain flag (expected in stream flags)")
            if not tcp_b64_found: print(" - Missing TCP b64 flag (expected in stream flags)")
            
    finally:
        if os.path.exists(filename):
            os.remove(filename)

def test_out_of_order():
    filename = "data/sample_ooo.pcap"
    create_ooo_pcap(filename)
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        stream_flags = stats.get('stream_flags', [])
        ooo_matches = [f['match'] for f in stream_flags if "flag{order_is_here}" in f['match']]
        ooo_found = bool(ooo_matches)
        
        if ooo_matches:
            print(f"  Found flags: {ooo_matches}")
        
        if ooo_found:
            print("[SUCCESS] test_out_of_order: Reassembly worked.")
        else:
            print("[FAILURE] test_out_of_order: Flag not found.")
            
    finally:
        if os.path.exists(filename):
            os.remove(filename)

def test_multiple_matches():
    filename = "data/sample_multi_match.pcap"
    create_multi_match_pcap(filename)
    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        stream_flags = stats.get('stream_flags', [])
        f1_matches = [f['match'] for f in stream_flags if "flag{one}" in f['match']]
        f2_matches = [f['match'] for f in stream_flags if "flag{two}" in f['match']]
        
        f1 = bool(f1_matches)
        f2 = bool(f2_matches)
        
        all_matches = f1_matches + f2_matches
        if all_matches:
            print(f"  Found flags: {all_matches}")
        
        if f1 and f2:
            print("[SUCCESS] test_multiple_matches: Both flags found.")
        else:
            print("[FAILURE] test_multiple_matches: Missing flags.")
            if not f1: print(" - Missing flag{one}")
            if not f2: print(" - Missing flag{two}")

    finally:
        if os.path.exists(filename):
            os.remove(filename)

def test_pico_ctf():
    filename = "data/trace.pcap"
    # filename = "data/sample_pico.pcap"
    
    # Only create sample if file doesn't exist
    if not os.path.exists(filename):
        print(f"File {filename} not found, generating dummy sample...")
        create_pico_pcap(filename)
        expected_flag = "picoCTF{this_is_a_pico_flag}"
    else:
        print(f"Using existing file: {filename}")
        expected_flag = None

    try:
        analyzer = PcapAnalyzer(filename)
        stats = analyzer.read_stats()
        
        stream_flags = stats.get('stream_flags', [])
        
        # Look for any picoCTF match
        pico_matches = [f['match'] for f in stream_flags if "picoCTF" in f['match']]
        
        if pico_matches:
            print(f"  Found flags: {pico_matches}")
            print("[SUCCESS] test_pico_ctf: picoCTF flag found.")
            
            # If we expected a specific dummy flag, verify it
            if expected_flag and expected_flag not in pico_matches:
                 print(f"  [WARN] Expected dummy flag {expected_flag} but got {pico_matches}")

        else:
            print(f"[FAILURE] test_pico_ctf: picoCTF flag NOT found in {filename}.")
            
    finally:
        # Don't delete if we didn't create it (or if user wants to keep it)
        # But for valid test cleanup of generated files:
        if os.path.exists(filename) and filename == "data/sample_pico.pcap":
            os.remove(filename)
        elif os.path.exists(filename):
             print(f"Keeping {filename}")

if __name__ == "__main__":
    print("Running new sample tests...")
    test_mixed_protocols()
    test_out_of_order()
    test_multiple_matches()
    test_pico_ctf()
