"""Decoding utilities for extracting flags from various encodings.

This module provides functions to decode data from common encodings
used to hide flags in CTF challenges, including Base64, ROT13, and
hexadecimal.
"""

import base64
import binascii
import codecs
from typing import Optional


def decode_base64(data: bytes) -> Optional[str]:
    """Decode Base64-encoded data to a UTF-8 string.

    Handles data that may contain null bytes or extra whitespace by
    stripping them before decoding.

    Args:
        data: Raw bytes that may contain Base64-encoded content.

    Returns:
        The decoded UTF-8 string if decoding succeeds, None otherwise.

    Example:
        >>> decode_base64(b'ZmxhZ3t0ZXN0fQ==')
        'flag{test}'
    """
    try:
        return base64.b64decode(
            data.replace(b'\x00', b'').strip()
        ).decode('utf-8', errors='ignore')
    except Exception:
        return None


def decode_rot13(data: str) -> Optional[str]:
    """Decode ROT13-encoded text.

    ROT13 is a simple letter substitution cipher that replaces each
    letter with the letter 13 positions after it in the alphabet.

    Args:
        data: A string that may be ROT13-encoded.

    Returns:
        The ROT13-decoded string if decoding succeeds, None otherwise.

    Example:
        >>> decode_rot13('synt{grfg}')
        'flag{test}'
    """
    try:
        return codecs.decode(data, 'rot_13')
    except Exception:
        return None


def decode_hex(data: bytes) -> Optional[str]:
    """Decode hexadecimal-encoded data to a UTF-8 string.

    Args:
        data: Raw bytes containing hexadecimal characters (0-9, a-f, A-F).

    Returns:
        The decoded UTF-8 string if decoding succeeds, None otherwise.

    Example:
        >>> decode_hex(b'666c61677b746573747d')
        'flag{test}'
    """
    try:
        return binascii.unhexlify(data).decode('utf-8', errors='ignore')
    except Exception:
        return None
