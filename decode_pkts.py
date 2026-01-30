import base64
import binascii
import codecs

def decode_base64(data):
    try:
        return base64.b64decode(data.replace(b'\x00', b'').strip()).decode('utf-8', errors='ignore')
    except Exception:
        return None

def decode_rot13(data):
    try:
        return codecs.decode(data, 'rot_13')
    except Exception:
        # rot13 usually doesn't fail on string input, but good to be safe if extended
        return None

def decode_hex(data):
    try:
        return binascii.unhexlify(data).decode('utf-8', errors='ignore')
    except Exception:
        return None


