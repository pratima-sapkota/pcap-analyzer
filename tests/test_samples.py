from pcap_analyzer.pcap_stats import PcapAnalyzer
import os
import sys

# Add tests directory to path to import generate_samples
sys.path.append(os.path.dirname(__file__))
from generate_samples import create_mixed_pcap, create_ooo_pcap, create_multi_match_pcap, create_pico_pcap

def test_scan_all_samples():
    """
    Scans all .pcap files in the data directory and finds possible flags.
    Generates known test samples before scanning and cleans them up after.
    """
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    # List of generated files to manage
    generated_files = {
        "sample_mixed.pcap": create_mixed_pcap,
        "sample_ooo.pcap": create_ooo_pcap,
        "sample_multi_match.pcap": create_multi_match_pcap,
        "sample_pico.pcap": create_pico_pcap
    }

    # Generate samples
    print(f"Generating samples in {data_dir}...")
    for filename, creator_func in generated_files.items():
        filepath = os.path.join(data_dir, filename)
        creator_func(filepath)

    try:
        # Scan all pcap files in the directory
        files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
        print(f"\nScanning {len(files)} pcap files in {data_dir}...")
        
        for f in files:
            filepath = os.path.join(data_dir, f)
            print(f"\nAnalyzing {filepath}...")
            
            try:
                analyzer = PcapAnalyzer(filepath)
                stats = analyzer.read_stats()
                
                # Collect flags from both single packet and reassembled streams
                flags = stats.get('flags', [])
                stream_flags = stats.get('stream_flags', [])
                
                # Extract the match strings
                packet_matches = [flag['match'] for flag in flags]
                stream_matches = [flag['match'] for flag in stream_flags]
                all_matches = packet_matches + stream_matches
                
                if all_matches:
                    print(f"  [SUCCESS] Found flags: {all_matches}")
                else:
                    print("  [INFO] No flags found.")
                    
            except Exception as e:
                print(f"  [ERROR] Failed to analyze {f}: {e}")

    finally:
        # Clean up generated files
        print("\nCleaning up generated samples...")
        for filename in generated_files.keys():
            filepath = os.path.join(data_dir, filename)
            if os.path.exists(filepath):
                os.remove(filepath)

if __name__ == "__main__":
    test_scan_all_samples()
