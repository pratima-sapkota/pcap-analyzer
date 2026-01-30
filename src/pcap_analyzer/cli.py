import sys
import json
import argparse
from .pcap_stats import PcapAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Analyze pcap files for flags.')
    parser.add_argument('pcap_file', help='Path to the pcap file')
    parser.add_argument('-p', '--pattern', action='append', help='Custom flag pattern (regex). Can be used multiple times.')
    
    args = parser.parse_args()
    
    pcap_file = args.pcap_file
    if not pcap_file.endswith('.pcap') and not pcap_file.endswith('.pcapng'):
        print("Warning: File extension is not .pcap or .pcapng")

    print(f"Analyzing {pcap_file}...")
    try:
        analyzer = PcapAnalyzer(pcap_file)
        stats = analyzer.read_stats()
        
        # Determine patterns used
        patterns = args.pattern if args.pattern else ["default"]

        print(json.dumps(stats, indent=4))
        
        flags = stats.get('flags', [])
        if flags:
            print("\n[+] Possible Flags Found (Single Packet):")
            for item in flags:
                print(f"  Packet {item['packet_num']}: {item['match']} (Encoding: {item.get('encoding', 'unknown')})")
        
        stream_flags = stats.get('stream_flags', [])
        if stream_flags:
            print("\n[+] Possible Flags Found (reassembled streams):")
            for item in stream_flags:
                print(f"  Stream {item['stream_id']}: {item['match']} (Encoding: {item.get('encoding', 'unknown')})")
                
        extracted_files = stats.get('extracted_files', [])
        if extracted_files:
            print("\n[+] Extracted Files:")
            for item in extracted_files:
                print(f"  {item['filename']} (Size: {item['size']} bytes) -> {item['path']}")
        
        if not flags and not stream_flags and not extracted_files:
            print("\n[-] No flags found with patterns:", patterns)
            
    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()