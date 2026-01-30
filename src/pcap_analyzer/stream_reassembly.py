from scapy.all import TCP, Raw
import re
from .decode_pkts import decode_base64, decode_rot13, decode_hex

class StreamAnalyzer:
    def __init__(self, packets):
        self.packets = packets

    def search_streams(self, patterns=None):
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}']
            
        results = []
        # Group by sessions (streams)
        # sessions() returns dict: 'Protocol src:sport > dst:dport' -> PacketList
        sessions = self.packets.sessions()
        
        for session_id, session_pkts in sessions.items():
            # We are primarily interested in TCP streams for reassembly
            # Check if majority of packets are TCP or just check the first one
            is_tcp = False
            for pkt in session_pkts:
                if pkt.haslayer(TCP):
                    is_tcp = True
                    break
            
            if not is_tcp:
                continue

            # Sort packets by SEQ number to reassemble correctly
            # Note: This is a simplistic reassembly. It assumes no retransmissions overlapping/gaps for now.
            try:
                sorted_pkts = sorted(session_pkts, key=lambda p: p[TCP].seq if p.haslayer(TCP) else 0)
            except Exception:
                sorted_pkts = session_pkts
            
            # Reassemble payload
            stream_payload = b""
            for pkt in sorted_pkts:
                if pkt.haslayer(Raw):
                    stream_payload += pkt[Raw].load
            
            if not stream_payload:
                continue

            # Decode and search
            candidates = []
            try:
                candidates.append(('plain', stream_payload.decode('utf-8', errors='ignore')))
            except: pass
            
            # Base64 (strip nulls and whitespace)
            try:
                # Often in streams b64 might be split, so reassembly helps here
                res = decode_base64(stream_payload)
                if res: candidates.append(('base64', res))
            except: pass
            
            # Rot13
            try:
                s = stream_payload.decode('utf-8', errors='ignore')
                res = decode_rot13(s)
                if res: candidates.append(('rot13', res))
            except: pass
            

            
             # Hex
            try:
                res = decode_hex(stream_payload)
                if res: candidates.append(('hex', res))
            except: pass

            # Also return the raw stream info for file extraction even if no flag format matches
            # But the structure is currently list of flag matches.
            # We should probably return a list of streams metadata + flags.
            
            # For backward compatibility with what we planned, let's keep search_flags returning flags.
            # BUT, we need a way to get streams.
            # Let's add a separate method or result.
            
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
        return results

    def get_reassembled_streams(self):
        """
        Returns a dictionary of stream_id -> payload bytes
        """
        streams = {}
        sessions = self.packets.sessions()
        
        for session_id, session_pkts in sessions.items():
            is_tcp = False
            for pkt in session_pkts:
                if pkt.haslayer(TCP):
                    is_tcp = True
                    break
            
            if not is_tcp:
                continue

            try:
                sorted_pkts = sorted(session_pkts, key=lambda p: p[TCP].seq if p.haslayer(TCP) else 0)
            except:
                sorted_pkts = session_pkts
            
            stream_payload = b""
            for pkt in sorted_pkts:
                if pkt.haslayer(Raw):
                    stream_payload += pkt[Raw].load
            
            if stream_payload:
                streams[session_id] = stream_payload
                
        return streams
