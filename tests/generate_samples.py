"""Sample pcap file generator for testing pcap-inspector.

This module provides functions to generate synthetic pcap files with
known flags for testing the pcap-inspector package. The generated files
contain various scenarios including split flags, out-of-order packets,
and different encodings.
"""

import base64
import os
from typing import Callable, List

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
from scapy.packet import Packet


def safe_wrpcap(filename: str, pkts: List[Packet]) -> None:
    """Write packets to a pcap file, creating directories as needed.

    Args:
        filename: Path to the output pcap file.
        pkts: List of Scapy packets to write.
    """
    output_dir = os.path.dirname(filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    wrpcap(filename, pkts)
    print(f"Created {filename}")


def create_mixed_pcap(filename: str) -> None:
    """Create a pcap with mixed protocol flags.

    Creates a pcap file containing:
    1. UDP packet with a single-packet flag
    2. TCP stream with plain text flag split across packets
    3. TCP stream with Base64-encoded flag split across packets

    Args:
        filename: Path for the output pcap file.

    Generated flags:
        - flag{udp_flag} (single UDP packet)
        - flag{tcp_plain} (split plain text)
        - flag{tcp_b64} (split Base64)
    """
    pkts: List[Packet] = []

    # 1. UDP Packet with flag
    pkts.append(
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        UDP(sport=5555, dport=1234) /
        Raw(load="UDP packet with flag{udp_flag} inside")
    )

    # 2. TCP Split Plain: "flag{tcp_plain}"
    p1 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=1001, dport=80, seq=100, flags="PA") /
        Raw(load="data before flag{tcp")
    )
    p2 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=1001, dport=80, seq=116, flags="PA") /
        Raw(load="_plain} data after")
    )
    pkts.extend([p1, p2])

    # 3. TCP Split Base64: flag{tcp_b64} -> ZmxhZ3t0Y3BfYjY0fQ==
    p3 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=1002, dport=80, seq=200, flags="PA") /
        Raw(load="ZmxhZ3t0Y")
    )
    p4 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=1002, dport=80, seq=209, flags="PA") /
        Raw(load="3BfYjY0fQ==")
    )
    pkts.extend([p3, p4])

    safe_wrpcap(filename, pkts)


def create_ooo_pcap(filename: str) -> None:
    """Create a pcap with out-of-order TCP packets.

    Tests the stream reassembly's ability to handle packets that
    arrive in a different order than their sequence numbers.

    Args:
        filename: Path for the output pcap file.

    Generated flags:
        - flag{order_is_here} (reassembled from out-of-order packets)
    """
    pkts: List[Packet] = []
    sport = 2001

    # flag{order_is_here} split into 3 packets, sent out of order
    p1 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=100, flags="PA") /
        Raw(load="flag{order")
    )
    p2 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=110, flags="PA") /
        Raw(load="_is")
    )
    p3 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=113, flags="PA") /
        Raw(load="_here}")
    )

    # Add in wrong order: P1, P3, P2
    pkts.extend([p1, p3, p2])

    safe_wrpcap(filename, pkts)


def create_multi_match_pcap(filename: str) -> None:
    """Create a pcap with multiple flags in one stream.

    Tests detection of multiple flags within a single TCP stream.

    Args:
        filename: Path for the output pcap file.

    Generated flags:
        - flag{one}
        - flag{two}
    """
    pkts: List[Packet] = []
    sport = 3001

    payload = "Start flag{one} Middle flag{two} End"
    part1 = payload[:10]   # "Start flag"
    part2 = payload[10:20]  # "{one} Midd"
    part3 = payload[20:]    # "le flag{two} End"

    p1 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=100, flags="PA") /
        Raw(load=part1)
    )
    p2 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=110, flags="PA") /
        Raw(load=part2)
    )
    p3 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=120, flags="PA") /
        Raw(load=part3)
    )

    pkts.extend([p1, p2, p3])

    safe_wrpcap(filename, pkts)


def create_pico_pcap(filename: str) -> None:
    """Create a pcap with a picoCTF formatted flag.

    Tests detection of picoCTF{...} flag format commonly used in
    picoCTF competitions.

    Args:
        filename: Path for the output pcap file.

    Generated flags:
        - picoCTF{this_is_a_pico_flag}
    """
    pkts: List[Packet] = []
    sport = 4001

    p1 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=100, flags="PA") /
        Raw(load="This is unexpected: picoCTF{th")
    )
    p2 = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=sport, dport=80, seq=130, flags="PA") /
        Raw(load="is_is_a_pico_flag}")
    )

    pkts.extend([p1, p2])

    safe_wrpcap(filename, pkts)


if __name__ == "__main__":
    DATA_DIR = "data"

    create_mixed_pcap(os.path.join(DATA_DIR, "sample_mixed.pcap"))
    create_ooo_pcap(os.path.join(DATA_DIR, "sample_ooo.pcap"))
    create_multi_match_pcap(os.path.join(DATA_DIR, "sample_multi_match.pcap"))
    create_pico_pcap(os.path.join(DATA_DIR, "sample_pico.pcap"))
