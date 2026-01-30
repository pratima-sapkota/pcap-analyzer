#!/usr/bin/env python3
"""PCAP file analyzer for CTF flag detection and file extraction.

This module provides the main PcapInspector class for analyzing packet
capture files, searching for hidden flags, and extracting files from
HTTP streams.
"""

import logging
import os
import re
import warnings
from collections import Counter
from typing import Any, Dict, List, Optional, TypedDict

from scapy.all import Raw, load_layer, rdpcap, sniff

from .decode_pkts import decode_base64, decode_hex, decode_rot13
from .file_extractor import ExtractedFileInfo, FileExtractor
from .stream_reassembly import StreamAnalyzer, StreamFlagMatch

# Suppress TLSSession deprecation warning
warnings.filterwarnings("ignore", message="TLSSession is deprecated")

# Load TLS layer for decryption support
load_layer("tls")


class FlagMatch(TypedDict):
    """Type definition for a flag match found in a single packet.

    Attributes:
        packet_num: 1-indexed packet number where the flag was found.
        match: The matched flag string.
        pattern: The regex pattern that matched.
        encoding: The encoding in which the flag was found.
    """

    packet_num: int
    match: str
    pattern: str
    encoding: str


class AnalysisStats(TypedDict):
    """Type definition for complete analysis statistics.

    Attributes:
        layers: Dictionary mapping layer names to occurrence counts.
        flags: List of flags found in individual packets.
        stream_flags: List of flags found in reassembled streams.
        extracted_files: List of files extracted from HTTP streams.
    """

    layers: Dict[str, int]
    flags: List[FlagMatch]
    stream_flags: List[StreamFlagMatch]
    extracted_files: List[ExtractedFileInfo]


class PcapInspector:
    """Analyzer for pcap/pcapng files to find CTF flags and extract files.

    This class provides comprehensive analysis of packet captures including:
    - Flag pattern searching with multiple encoding support
    - TCP stream reassembly for split flag detection
    - TLS decryption with private key support
    - File extraction from HTTP responses

    Attributes:
        pcap_file: Path to the pcap/pcapng file being analyzed.
        key_file: Optional path to a TLS private key for decryption.
        packets: Loaded packet list from the capture file.

    Example:
        >>> analyzer = PcapInspector('capture.pcap', key_file='server.key')
        >>> stats = analyzer.read_stats()
        >>> for flag in stats['flags']:
        ...     print(f"Found: {flag['match']}")
    """

    def __init__(
        self,
        pcap_file: str,
        key_file: Optional[str] = None
    ) -> None:
        """Initialize the PCAP analyzer.

        Args:
            pcap_file: Path to the pcap or pcapng file to analyze.
            key_file: Optional path to a PEM-formatted TLS private key
                for decrypting TLS traffic.
        """
        self.pcap_file = pcap_file
        self.key_file = key_file
        self.packets = self._load_packets()

    def _load_packets(self) -> Any:
        """Load packets from pcap file with optional TLS decryption.

        If a key_file is provided and exists, attempts to use Scapy's
        TLSSession for decryption. Falls back to standard loading on failure.

        Returns:
            Scapy PacketList containing the loaded packets.

        Raises:
            FileNotFoundError: If the pcap file does not exist.
        """
        if self.key_file and os.path.exists(self.key_file):
            try:
                from scapy.layers.tls.cert import PrivKey
                from scapy.layers.tls.session import TLSSession

                # Load the private key for TLS decryption
                pk = PrivKey(self.key_file)

                # Suppress the deprecation warning from Scapy's logging
                scapy_logger = logging.getLogger("scapy")
                original_level = scapy_logger.level
                scapy_logger.setLevel(logging.ERROR)
                try:
                    # Use sniff with TLSSession to decrypt TLS traffic
                    packets = sniff(
                        offline=self.pcap_file,
                        session=TLSSession(server_rsa_key=pk)
                    )
                finally:
                    scapy_logger.setLevel(original_level)
                return packets

            except Exception as e:
                # Fall back to regular rdpcap if TLS decryption fails
                print(
                    f"Warning: TLS decryption failed ({e}), "
                    "falling back to standard loading"
                )
                return rdpcap(self.pcap_file)
        else:
            return rdpcap(self.pcap_file)

    def search_flags(
        self,
        patterns: Optional[List[str]] = None
    ) -> List[FlagMatch]:
        """Search individual packets for flag patterns.

        Searches the Raw layer payload of each packet for flag patterns,
        attempting multiple decodings (plain text, Base64, ROT13, hex).

        Args:
            patterns: List of regex patterns to search for. Defaults to
                common CTF formats: flag{...}, CTF{...}, picoCTF{...}.

        Returns:
            List of FlagMatch dictionaries for each flag found.
        """
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}', r'picoCTF\{.*?\}']

        results: List[FlagMatch] = []

        for i, pkt in enumerate(self.packets):
            if not pkt.haslayer(Raw):
                continue

            payload: bytes = pkt[Raw].load
            candidates = self._get_payload_decodings(payload)

            for enc_name, decoded_val in candidates:
                for pattern in patterns:
                    matches = re.findall(pattern, decoded_val)
                    for match in matches:
                        results.append({
                            'packet_num': i + 1,
                            'match': match,
                            'pattern': pattern,
                            'encoding': enc_name
                        })

        return results

    def _get_payload_decodings(
        self,
        payload: bytes
    ) -> List[tuple[str, str]]:
        """Get various decoded versions of a payload.

        Args:
            payload: Raw bytes to decode.

        Returns:
            List of (encoding_name, decoded_string) tuples.
        """
        candidates: List[tuple[str, str]] = []

        # 1. Plain UTF-8
        try:
            candidates.append(
                ('plain', payload.decode('utf-8', errors='ignore'))
            )
        except Exception:
            pass

        # 2. Base64
        try:
            res = decode_base64(payload)
            if res:
                candidates.append(('base64', res))
        except Exception:
            pass

        # 3. ROT13 (on string repr)
        try:
            s = payload.decode('utf-8', errors='ignore')
            res = decode_rot13(s)
            if res:
                candidates.append(('rot13', res))
        except Exception:
            pass

        # 4. Hex
        try:
            res = decode_hex(payload)
            if res:
                candidates.append(('hex', res))
        except Exception:
            pass

        return candidates

    @staticmethod
    def get_packet_layers(pkt: Any) -> List[str]:
        """Get list of layer names in a packet.

        Args:
            pkt: A Scapy packet object.

        Returns:
            List of layer names from outermost to innermost.
        """
        layers: List[str] = []
        current_layer = pkt

        while current_layer:
            layers.append(current_layer.name)
            current_layer = current_layer.payload
            if current_layer is None or current_layer.name == "NoPayload":
                break

        return layers

    def analyze_layers(self) -> Dict[str, int]:
        """Analyze protocol layer distribution in the capture.

        Returns:
            Dictionary mapping layer names to occurrence counts.
        """
        layer_list: List[str] = []
        for pkt in self.packets:
            layer_list.extend(self.get_packet_layers(pkt))
        return dict(Counter(layer_list))

    def read_stats(self) -> AnalysisStats:
        """Perform complete analysis of the pcap file.

        Runs all analysis functions and returns comprehensive statistics
        including layer counts, flags from packets and streams, and
        extracted files.

        Returns:
            AnalysisStats dictionary with complete analysis results.
        """
        stats: AnalysisStats = {
            'layers': self.analyze_layers(),
            'flags': self.search_flags(),
            'stream_flags': [],
            'extracted_files': []
        }

        # Stream Analysis
        stream_analyzer = StreamAnalyzer(self.packets)
        stats['stream_flags'] = stream_analyzer.search_streams()

        # File Extraction
        file_extractor = FileExtractor()
        extracted: List[ExtractedFileInfo] = []
        streams = stream_analyzer.get_reassembled_streams()

        for sid, payload in streams.items():
            files = file_extractor.extract_from_stream(sid, payload)
            extracted.extend(files)

        stats['extracted_files'] = extracted

        return stats
