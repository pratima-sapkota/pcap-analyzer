"""TCP stream reassembly and flag searching for network captures.

This module provides functionality to reassemble TCP streams from packet
captures and search for flags within the reassembled data. It handles
out-of-order packets, retransmissions, and various encodings.
"""

import gzip
import re
from typing import Any, Dict, List, Optional, TypedDict

from scapy.all import Raw, TCP
from scapy.plist import PacketList

from .decode_pkts import decode_base64, decode_hex, decode_rot13


class StreamFlagMatch(TypedDict):
    """Type definition for a flag match found in a stream.

    Attributes:
        stream_id: Identifier of the stream where flag was found.
        match: The matched flag string.
        pattern: The regex pattern that matched.
        encoding: The encoding in which the flag was found (e.g., 'plain', 'base64').
    """

    stream_id: str
    match: str
    pattern: str
    encoding: str


class StreamAnalyzer:
    """Analyzes and reassembles TCP streams to search for hidden flags.

    This class takes a list of packets, groups them by TCP session,
    reassembles the payload data in sequence order, and searches for
    flag patterns in various encodings.

    Attributes:
        packets: The packet list to analyze.

    Example:
        >>> from scapy.all import rdpcap
        >>> packets = rdpcap('capture.pcap')
        >>> analyzer = StreamAnalyzer(packets)
        >>> flags = analyzer.search_streams()
        >>> for flag in flags:
        ...     print(f"Found: {flag['match']} in {flag['stream_id']}")
    """

    def __init__(self, packets: PacketList) -> None:
        """Initialize the stream analyzer.

        Args:
            packets: A Scapy PacketList containing the packets to analyze.
        """
        self.packets = packets

    def search_streams(
        self,
        patterns: Optional[List[str]] = None
    ) -> List[StreamFlagMatch]:
        """Search reassembled TCP streams for flag patterns.

        Reassembles TCP streams, attempts various decodings (plain text,
        Base64, ROT13, hex, gzip), and searches for flag patterns in
        each decoded form.

        Args:
            patterns: List of regex patterns to search for. Defaults to
                common CTF flag formats: flag{...}, CTF{...}, picoCTF{...}.

        Returns:
            List of StreamFlagMatch dictionaries for each flag found.
        """
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}', r'picoCTF\{.*?\}']

        results: List[StreamFlagMatch] = []
        sessions = self.packets.sessions()

        for session_id, session_pkts in sessions.items():
            try:
                # Check if this is a TCP session
                is_tcp = any(pkt.haslayer(TCP) for pkt in session_pkts)
                if not is_tcp:
                    continue

                # Sort and deduplicate packets by sequence number
                sorted_pkts = self._get_sorted_unique_packets(session_pkts)

                # Reassemble payload
                stream_payload = self._reassemble_payload(sorted_pkts)

                if not stream_payload:
                    continue

                # Try various decodings and search for patterns
                candidates = self._get_decoded_candidates(stream_payload)

                for enc_name, decoded_val in candidates:
                    for pattern in patterns:
                        matches = re.findall(pattern, decoded_val)
                        for match in matches:
                            results.append({
                                'stream_id': session_id,
                                'match': match,
                                'pattern': pattern,
                                'encoding': enc_name
                            })

            except Exception as e:
                # Log errors but continue processing other streams
                print(f"DEBUG: Error in search_streams for session {session_id}: {e}")
                import traceback
                traceback.print_exc()

        return results

    def _get_sorted_unique_packets(self, session_pkts: PacketList) -> List[Any]:
        """Sort packets by sequence number and remove duplicates.

        Args:
            session_pkts: Packets from a single TCP session.

        Returns:
            List of unique packets sorted by TCP sequence number.
        """
        try:
            unique_pkts: Dict[int, Any] = {}
            for pkt in session_pkts:
                if pkt.haslayer(TCP):
                    seq = pkt[TCP].seq
                    if seq not in unique_pkts:
                        unique_pkts[seq] = pkt
            return sorted(unique_pkts.values(), key=lambda p: p[TCP].seq)
        except Exception:
            return list(session_pkts)

    def _reassemble_payload(self, sorted_pkts: List[Any]) -> bytes:
        """Reassemble payload bytes from sorted packets.

        Handles both decrypted TLS application data and raw TCP payloads.
        Skips encrypted TLS data that hasn't been decrypted.

        Args:
            sorted_pkts: Packets sorted by sequence number.

        Returns:
            Reassembled payload as bytes.
        """
        stream_payload = b""

        for pkt in sorted_pkts:
            found_tls_data = False

            # Check for decrypted TLS application data first
            if pkt.haslayer('TLSApplicationData'):
                try:
                    stream_payload += bytes(pkt['TLSApplicationData'].data)
                    found_tls_data = True
                except Exception:
                    pass

            # Try to extract from TLS layer if not found via direct layer
            if not found_tls_data and pkt.haslayer('TLS'):
                layer = pkt['TLS']
                while layer:
                    if hasattr(layer, 'type') and layer.type == 23:
                        pass  # Application Data type
                    layer = layer.payload

            # Fall back to Raw layer
            if not found_tls_data and pkt.haslayer(Raw):
                val = pkt[Raw].load
                # Skip encrypted TLS Application Data (0x17 0x03)
                if len(val) > 2 and val[0] == 0x17 and val[1] == 0x03:
                    pass
                else:
                    stream_payload += val

        return stream_payload

    def _get_decoded_candidates(
        self,
        stream_payload: bytes
    ) -> List[tuple[str, str]]:
        """Get decoded versions of the payload in various encodings.

        Args:
            stream_payload: Raw payload bytes to decode.

        Returns:
            List of (encoding_name, decoded_string) tuples.
        """
        candidates: List[tuple[str, str]] = []

        # Plain UTF-8
        try:
            candidates.append(
                ('plain', stream_payload.decode('utf-8', errors='ignore'))
            )
        except Exception:
            pass

        # GZIP decompression
        try:
            header_sep = b'\r\n\r\n'
            parts = stream_payload.split(header_sep, 1)
            to_decompress = parts[1] if len(parts) == 2 else stream_payload
            decompressed = gzip.decompress(to_decompress)
            candidates.append(
                ('gzip', decompressed.decode('utf-8', errors='ignore'))
            )
        except Exception:
            pass

        # Base64
        try:
            res = decode_base64(stream_payload)
            if res:
                candidates.append(('base64', res))
        except Exception:
            pass

        # ROT13
        try:
            s = stream_payload.decode('utf-8', errors='ignore')
            res = decode_rot13(s)
            if res:
                candidates.append(('rot13', res))
        except Exception:
            pass

        # Hex
        try:
            res = decode_hex(stream_payload)
            if res:
                candidates.append(('hex', res))
        except Exception:
            pass

        return candidates

    def get_reassembled_streams(self) -> Dict[str, bytes]:
        """Get all reassembled TCP streams as a dictionary.

        Useful for extracting files or performing custom analysis on
        the reassembled stream data.

        Returns:
            Dictionary mapping stream_id to reassembled payload bytes.
        """
        streams: Dict[str, bytes] = {}
        sessions = self.packets.sessions()

        for session_id, session_pkts in sessions.items():
            # Check if TCP session
            is_tcp = any(pkt.haslayer(TCP) for pkt in session_pkts)
            if not is_tcp:
                continue

            try:
                sorted_pkts = sorted(
                    session_pkts,
                    key=lambda p: p[TCP].seq if p.haslayer(TCP) else 0
                )
            except Exception:
                sorted_pkts = list(session_pkts)

            stream_payload = b""
            for pkt in sorted_pkts:
                found_tls = False
                if pkt.haslayer('TLSApplicationData'):
                    try:
                        stream_payload += bytes(pkt['TLSApplicationData'].data)
                        found_tls = True
                    except Exception:
                        pass

                if not found_tls and pkt.haslayer(Raw):
                    val = pkt[Raw].load
                    # Skip encrypted TLS App Data
                    if len(val) > 2 and val[0] == 0x17 and val[1] == 0x03:
                        pass
                    else:
                        stream_payload += val

            if stream_payload:
                streams[session_id] = stream_payload

        return streams
