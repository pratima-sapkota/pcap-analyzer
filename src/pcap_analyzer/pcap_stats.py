#!/usr/bin/env python3

from scapy.all import rdpcap, Raw
from collections import Counter
import re
from .decode_pkts import decode_base64, decode_rot13, decode_hex
from .stream_reassembly import StreamAnalyzer

class PcapAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def search_flags(self, patterns=None):
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}']
        
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
        
        return stats
