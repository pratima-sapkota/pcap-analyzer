"""Test suite for pcap-inspector sample file scanning.

This module provides tests that scan pcap files in the data directory
for flags, including both pre-existing samples and dynamically
generated test files.
"""

import os
import sys
from typing import Callable, Dict, List

from pcap_inspector import PcapInspector

# Add tests directory to path to import generate_samples
sys.path.append(os.path.dirname(__file__))
from generate_samples import (
    create_mixed_pcap,
    create_multi_match_pcap,
    create_ooo_pcap,
    create_pico_pcap,
)


def test_scan_all_samples() -> None:
    """Scan all pcap files in the data directory and find flags.

    This test:
    1. Generates known test sample pcap files
    2. Scans all .pcap and .pcapng files in the data directory
    3. Reports found flags with color-coded output
    4. Cleans up generated sample files after scanning

    The test uses TLS key files when available (matching basename
    with .key extension).

    Note:
        This test does not assert specific flags; it's designed for
        manual verification and exploration of pcap files.
    """
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    # Map of generated files to their creator functions
    generated_files: Dict[str, Callable[[str], None]] = {
        "sample_mixed.pcap": create_mixed_pcap,
        "sample_ooo.pcap": create_ooo_pcap,
        "sample_multi_match.pcap": create_multi_match_pcap,
        "sample_pico.pcap": create_pico_pcap
    }

    # ANSI color codes for terminal output
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    # Generate test sample files
    print(f"Generating samples in {data_dir}...")
    for filename, creator_func in generated_files.items():
        filepath = os.path.join(data_dir, filename)
        creator_func(filepath)

    try:
        # Find all pcap files in the directory
        files: List[str] = [
            f for f in os.listdir(data_dir)
            if f.endswith('.pcap') or f.endswith('.pcapng')
        ]
        print(f"\nScanning {len(files)} pcap/pcapng files in {data_dir}...")

        for f in files:
            filepath = os.path.join(data_dir, f)
            print(f"\nAnalyzing {filepath}...")

            # Check for matching TLS key file
            key_file: str | None = None
            base_name = os.path.splitext(f)[0]
            potential_key = os.path.join(data_dir, f"{base_name}.key")
            if os.path.exists(potential_key):
                key_file = potential_key
                print(f"  Using TLS key: {key_file}")

            try:
                analyzer = PcapInspector(filepath, key_file=key_file)
                stats = analyzer.read_stats()

                # Collect flags from both single packet and reassembled streams
                flags = stats.get('flags', [])
                stream_flags = stats.get('stream_flags', [])

                # Extract the match strings
                packet_matches: List[str] = [flag['match'] for flag in flags]
                stream_matches: List[str] = [
                    flag['match'] for flag in stream_flags
                ]
                all_matches = packet_matches + stream_matches

                if all_matches:
                    flags_str = ", ".join(all_matches)
                    print(
                        f"  {GREEN}[SUCCESS]{RESET} Found flags: "
                        f"{BOLD}{flags_str}{RESET}"
                    )
                else:
                    print(f"  {YELLOW}[WARNING]{RESET} No flags found.")

            except Exception as e:
                print(f"  {RED}[ERROR]{RESET} Failed to analyze {f}: {e}")

    finally:
        # Clean up generated sample files
        print("\nCleaning up generated samples...")
        for filename in generated_files.keys():
            filepath = os.path.join(data_dir, filename)
            if os.path.exists(filepath):
                os.remove(filepath)


if __name__ == "__main__":
    test_scan_all_samples()
