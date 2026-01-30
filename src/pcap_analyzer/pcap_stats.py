#!/usr/bin/env python3

from scapy.all import rdpcap, Raw, sniff, load_layer
from collections import Counter
import re
import os
import warnings
from .decode_pkts import decode_base64, decode_rot13, decode_hex
from .stream_reassembly import StreamAnalyzer
from .file_extractor import FileExtractor

# Suppress TLSSession deprecation warning
warnings.filterwarnings("ignore", message="TLSSession is deprecated")

# Load TLS layer for decryption support
load_layer("tls")

class PcapAnalyzer:
    def __init__(self, pcap_file, key_file=None):
        self.pcap_file = pcap_file
        self.key_file = key_file
        self.packets = self._load_packets()

    def _load_packets(self):
        """Load packets from pcap file, with optional TLS decryption."""
        if self.key_file and os.path.exists(self.key_file):
            try:
                from scapy.layers.tls.session import TLSSession
                from scapy.layers.tls.cert import PrivKey
                import logging
                
                # Load the private key for TLS decryption
                pk = PrivKey(self.key_file)
                
                # Suppress the deprecation warning from Scapy's logging
                scapy_logger = logging.getLogger("scapy")
                original_level = scapy_logger.level
                scapy_logger.setLevel(logging.ERROR)
                try:
                    # Use sniff with TLSSession to decrypt TLS traffic
                    packets = sniff(offline=self.pcap_file, session=TLSSession(server_rsa_key=pk))
                finally:
                    scapy_logger.setLevel(original_level)
                return packets
            except Exception as e:
                # Fall back to regular rdpcap if TLS decryption fails
                print(f"Warning: TLS decryption failed ({e}), falling back to standard loading")
                return rdpcap(self.pcap_file)
        else:
            return rdpcap(self.pcap_file)

    def search_flags(self, patterns=None):
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}', r'picoCTF\{.*?\}']
        
        results = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                
                # specific decoding attempts
                candidates = []
                # 1. Plain UTF-8
                try:
                    candidates.append(('plain', payload.decode('utf-8', errors='ignore')))
                except:
                    pass
                    
                # 2. Base64
                try:
                    # simplistic check: if valid b64
                    # DEBUG
                    res = decode_base64(payload)
                    if res: candidates.append(('base64', res))
                except: pass

                # 3. Rot13 (on string repr)
                try:
                    s = payload.decode('utf-8', errors='ignore')
                    res = decode_rot13(s)
                    if res: candidates.append(('rot13', res))
                except: pass
                
                # 4. Hex
                try:
                    res = decode_hex(payload)
                    if res: candidates.append(('hex', res))
                except: pass

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

    @staticmethod
    def get_packet_layers(pkt):

        layers = []
        current_layer = pkt
        while current_layer:
            layers.append(current_layer.name)
            current_layer = current_layer.payload
            if current_layer is None or current_layer.name == "NoPayload":
                break
        return layers

    def analyze_layers(self):
        layer_list = []
        for pkt in self.packets:
            layer_list.extend(self.get_packet_layers(pkt))
        return dict(Counter(layer_list))

    def read_stats(self):
        stats = {}
        stats['layers'] = self.analyze_layers()
        stats['flags'] = self.search_flags()
        
        # Stream Analysis
        stream_analyzer = StreamAnalyzer(self.packets)
        stats['stream_flags'] = stream_analyzer.search_streams()
        
        # File Extraction
        file_extractor = FileExtractor() # uses default 'extracted_files'
        extracted = []
        streams = stream_analyzer.get_reassembled_streams()
        for sid, payload in streams.items():
            files = file_extractor.extract_from_stream(sid, payload)
            extracted.extend(files)
            
        stats['extracted_files'] = extracted
        
        return stats
