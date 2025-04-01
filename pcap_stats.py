#!/usr/bin/env python3
from scapy.all import rdpcap
from collections import Counter

class PcapAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

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
        return self.analyze_layers()
