
from scapy.all import rdpcap, load_layer, conf
load_layer("tls")
from scapy.layers.tls.cert import PrivKey

def test_decryption(pcap_file, key_file):
    print(f"Testing decryption on {pcap_file} with {key_file}")
    
    # Load key
    try:
        pk = PrivKey(key_file)
    except Exception as e:
        print(f"Failed to load key: {e}")
        return

    # Configure Scapy to use the key
    # Simple association: port 443 -> key (assuming server is on 443)
    # In Scapy 2.4.3+ we usually populate conf.tls_session.
    
    # We will try to read with a TLS session context
    from scapy.layers.tls.session import TLSSession
    
    try:
        # We need to supply the server key to the session
        # Scapy TLS session usually takes a list of keys or a mapping
        
        # NOTE: Scapy's TLSSession is often used like: sniff(session=TLSSession(server_rsa_key=pk))
        # For reading a pcap, we can emulate this.
        
        from scapy.all import sniff
        packets = sniff(offline=pcap_file, session=TLSSession(server_rsa_key=pk))
        
        decrypted_count = 0
        for pkt in packets:
            if pkt.haslayer('TLSApplicationData'):
                 # Check if we can see data
                 app_data = pkt['TLSApplicationData'].data
                 # If it helps, print first few chars
                 print(f"Packet {pkt.summary()}: {len(app_data)} bytes")
                 decrypted_count += 1
                 
                 if b'HTTP' in app_data or b'GET' in app_data:
                     print(f"  [POTENTIAL HTTP] {app_data[:50]}")
        
        print(f"Total packets with TLS App Data: {decrypted_count}")
        
    except Exception as e:
        print(f"Decryption failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_decryption("data/capture.pcap", "data/picopico.key")
