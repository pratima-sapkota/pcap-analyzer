"""Command-line interface for pcap-inspector.

This module provides the main entry point for the pcap-inspector CLI tool,
which analyzes pcap/pcapng files to find hidden flags commonly used in
CTF (Capture The Flag) challenges.
"""

import argparse
import json
import sys
import traceback
from typing import List, Optional

from .pcap_stats import PcapInspector


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the pcap-inspector CLI.

    Analyzes a pcap file for flags, extracts files from HTTP streams,
    and displays results to stdout.

    Args:
        args: Command-line arguments. If None, uses sys.argv.

    Returns:
        Exit code: 0 for success, 1 for errors.

    Example:
        Command line usage::

            $ pcap-inspector capture.pcap
            $ pcap-inspector capture.pcap -p 'secret\\{.*?\\}'
    """
    parser = argparse.ArgumentParser(
        description='Analyze pcap files for flags.',
        prog='pcap-inspector'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to the pcap or pcapng file'
    )
    parser.add_argument(
        '-p', '--pattern',
        action='append',
        help='Custom flag pattern (regex). Can be used multiple times.'
    )

    parsed_args = parser.parse_args(args)

    pcap_file: str = parsed_args.pcap_file
    if not pcap_file.endswith('.pcap') and not pcap_file.endswith('.pcapng'):
        print("Warning: File extension is not .pcap or .pcapng")

    print(f"Analyzing {pcap_file}...")
    try:
        analyzer = PcapInspector(pcap_file)
        stats = analyzer.read_stats()

        # Determine patterns used
        patterns: List[str] = parsed_args.pattern if parsed_args.pattern else ["default"]

        print(json.dumps(stats, indent=4))

        flags = stats.get('flags', [])
        if flags:
            print("\n[+] Possible Flags Found (Single Packet):")
            for item in flags:
                print(
                    f"  Packet {item['packet_num']}: {item['match']} "
                    f"(Encoding: {item.get('encoding', 'unknown')})"
                )

        stream_flags = stats.get('stream_flags', [])
        if stream_flags:
            print("\n[+] Possible Flags Found (reassembled streams):")
            for item in stream_flags:
                print(
                    f"  Stream {item['stream_id']}: {item['match']} "
                    f"(Encoding: {item.get('encoding', 'unknown')})"
                )

        extracted_files = stats.get('extracted_files', [])
        if extracted_files:
            print("\n[+] Extracted Files:")
            for item in extracted_files:
                print(
                    f"  {item['filename']} (Size: {item['size']} bytes) "
                    f"-> {item['path']}"
                )

        if not flags and not stream_flags and not extracted_files:
            print("\n[-] No flags found with patterns:", patterns)

        return 0

    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
        return 1
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())