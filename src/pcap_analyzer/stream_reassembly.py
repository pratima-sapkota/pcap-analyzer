from scapy.all import TCP, Raw
import re
from .decode_pkts import decode_base64, decode_rot13, decode_hex

class StreamAnalyzer:
    def __init__(self, packets):
        self.packets = packets

    def search_streams(self, patterns=None):
        if patterns is None:
            patterns = [r'flag\{.*?\}', r'CTF\{.*?\}', r'picoCTF\{.*?\}']
            
        results = []
        # Group by sessions (streams)
        # sessions() returns dict: 'Protocol src:sport > dst:dport' -> PacketList
        sessions = self.packets.sessions()
        
        for session_id, session_pkts in sessions.items():
            try:
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
                # Handle Retransmissions: Deduplicate by Sequence Number
                try:
                    if is_tcp:
                        unique_pkts = {}
                        for pkt in session_pkts:
                            if pkt.haslayer(TCP):
                                seq = pkt[TCP].seq
                                # simple dedupe: keep first seen
                                if seq not in unique_pkts:
                                    unique_pkts[seq] = pkt
                        sorted_pkts = sorted(unique_pkts.values(), key=lambda p: p[TCP].seq)
                    else:
                        sorted_pkts = session_pkts
                except Exception:
                    sorted_pkts = session_pkts
                
                # Reassemble payload
                stream_payload = b""
                # Reassemble payload
                stream_payload = b""
                # Reassemble payload
                stream_payload = b""
                for i, pkt in enumerate(sorted_pkts):
                    found_tls_data = False
                    
                    # Check for decrypted app data explicitly first (most reliable if decrypted)
                    if pkt.haslayer('TLSApplicationData'):
                         try:
                             # Append the actual data bytes, not the whole packet
                             stream_payload += bytes(pkt['TLSApplicationData'].data)
                             found_tls_data = True
                         except: pass
                    else: 
                         pass
                    
                    # If not found via direct layer, try delving into TLS layer (less reliable/complex)
                    if not found_tls_data and pkt.haslayer('TLS'):
                        l = pkt['TLS']
                        while l:
                            if hasattr(l, 'type') and l.type == 23: # Application Data
                                 # Try to get data if simpler check failed
                                 pass 
                            l = l.payload
                    
                    if not found_tls_data:
                         if pkt.haslayer(Raw):
                             # If it starts with 0x16 0x03, it's likely encrypted TLS handshake/data
                             val = pkt[Raw].load
                             # 0x17 is Application Data (encrypted), 0x16 is Handshake
                             # We definitely want to skip Encrypted Application Data (0x17) as we want decrypted.
                             # We might want to keep Handshake (0x16) for non-decrypted analysis?
                             if len(val) > 2 and val[0] == 0x17 and val[1] == 0x03:
                                 pass # Skip encrypted TLS Application Data
                             else:
                                 stream_payload += val
                
                if not stream_payload:
                    continue

                # Decode and search
                candidates = []
                try:
                    candidates.append(('plain', stream_payload.decode('utf-8', errors='ignore')))
                except: pass
                
                # GZIP (New)
                try:
                    # HTTP body extraction for GZIP
                    # Looking for \r\n\r\n
                    header_sep = b'\r\n\r\n'
                    parts = stream_payload.split(header_sep, 1)
                    to_decompress = stream_payload
                    if len(parts) == 2:
                        # Check if headers indicate gzip, or just try decompressing the body
                        # The body is parts[1]
                        to_decompress = parts[1]
                    
                    import gzip
                    decompressed = gzip.decompress(to_decompress)
                    dec_str = decompressed.decode('utf-8', errors='ignore')
                    # candidates.append(('gzip', dec_str))
                    # print(f"DEBUG: GZIP Success for stream {session_id}! Content start: {dec_str[:20]}")
                    # We append GZIP success to candidates
                    candidates.append(('gzip', dec_str))
                except Exception as e: 
                    pass


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
            except Exception as e:
                print(f"DEBUG: Error in search_streams for session {session_id}: {e}")
                import traceback
                traceback.print_exc()
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
                found_tls = False
                if pkt.haslayer('TLSApplicationData'):
                    try:
                        stream_payload += bytes(pkt['TLSApplicationData'].data)
                        found_tls = True
                    except: pass
                
                if not found_tls and pkt.haslayer(Raw):
                     val = pkt[Raw].load
                     # Skip encrypted TLS App Data if mixed with decrypted checks? 
                     # Actually if we are here, we probably didn't find decrypted data or it's not TLS.
                     # But consistent with search_streams:
                     if len(val) > 2 and val[0] == 0x17 and val[1] == 0x03:
                         pass 
                     else:
                        stream_payload += val
            
            if stream_payload:
                streams[session_id] = stream_payload
                
        return streams
