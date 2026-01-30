"""pcap-inspector: A Python package for analyzing pcap files and finding CTF flags.

This package provides tools for analyzing network packet captures to find
hidden flags commonly used in CTF (Capture The Flag) challenges. It supports
multiple encodings, TCP stream reassembly, TLS decryption, and file extraction.

Example:
    Basic usage::

        from pcap_inspector import PcapInspector

        analyzer = PcapInspector('capture.pcap')
        stats = analyzer.read_stats()

        for flag in stats['flags']:
            print(f"Found: {flag['match']}")

    With TLS decryption::

        analyzer = PcapInspector('capture.pcap', key_file='server.key')
        stats = analyzer.read_stats()
"""

__version__ = "0.1.0"
__author__ = "Pratima Sapkota"

from .decode_pkts import decode_base64, decode_hex, decode_rot13
from .file_extractor import ExtractedFileInfo, FileExtractor
from .pcap_stats import AnalysisStats, FlagMatch, PcapInspector
from .stream_reassembly import StreamAnalyzer, StreamFlagMatch

__all__ = [
    # Main analyzer class
    "PcapInspector",
    # Supporting classes
    "StreamAnalyzer",
    "FileExtractor",
    # Type definitions
    "AnalysisStats",
    "FlagMatch",
    "StreamFlagMatch",
    "ExtractedFileInfo",
    # Utility functions
    "decode_base64",
    "decode_rot13",
    "decode_hex",
]
