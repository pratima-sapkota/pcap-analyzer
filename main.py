# #!/usr/bin/env python3

import sys
import json
from pcap_stats import PcapAnalyzer

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_pcap.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not pcap_file.endswith('.pcap'):
        print("Please provide a valid pcap file.")
        sys.exit(1)

    print(f"Analyzing {pcap_file}...")
    try:
        with open(pcap_file, 'r') as f:
            if f.readable():
                # Call the read_stats function from pcap_stats.py
                analyzer = PcapAnalyzer(pcap_file)
                stats = analyzer.read_stats()
                print(json.dumps(stats, indent=4))
            else:
                print(f"File {pcap_file} is empty.")
                sys.exit(1)
    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()