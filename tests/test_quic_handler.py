import pytest
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.quic_handler import QuicHandler

def test_decode_varint_basic():
    q = QuicHandler()
    # 1 byte
    val, l = q._decode_varint(bytes([0b00000010]))
    assert val == 2 and l == 1
    # 2 bytes
    val, l = q._decode_varint(bytes([0b01000010, 0x2A]))  # top2 bits 01 => 2 bytes, value low 6 bits
    assert l == 2
    # 4 bytes
    val, l = q._decode_varint(bytes([0b10000001, 0x00, 0x00, 0x01]))
    assert l == 4
    # 8 bytes
    val, l = q._decode_varint(bytes([0b11000001] + [0]*7))
    assert l == 8

def test_scan_frames_synthetic_crypto_padding():
    q = QuicHandler()
    # header len emulate
    hdr = b"\xc0" + b"\x00\x00\x00\x01" + b"\x08"+b"A"*8 + b"\x08"+b"B"*8 + b"\x00"  # token len=0
    # length varint (1B ok)
    hdr += b"\x01"  # len placeholder
    # Packet number 1B
    hdr += b"\x00"
    start = len(hdr)
    # CRYPTO(0x06) + off=0 (1B) + len=4 (1B) + data(4B)
    frames = b"\x06" + b"\x00" + b"\x04" + b"CH12"
    # PADDING
    frames += b"\x00"*10
    payload = hdr + frames
    frames_found = q._scan_frames(payload, start)
    types = [t for _,_,t in frames_found]
    assert "CRYPTO" in types and "PADDING" in types
