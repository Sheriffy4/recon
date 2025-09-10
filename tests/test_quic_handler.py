import pytest
from core.quic_handler import QuicHandler

def test_decode_varint_basic():
    q = QuicHandler()
    v, l = q._decode_varint(bytes([0x2a]))
    assert v == 0x2a and l == 1
    v, l = q._decode_varint(bytes([0x40|0x01, 0x23]))
    assert l == 2

def test_scan_frames_synthetic():
    q = QuicHandler()
    header = b"\xC0" + b"\x00\x00\x00\x01" + b"\x08"+b"\x00"*8 + b"\x08"+b"\x00"*8 + b"\x00" + b"\x40\x00" + b"\x00"
    start = len(header)
    body = b"\x06" + b"\x00" + b"\x0a" + b"\x11"*10 + b"\x00"*3
    frames = q._scan_frames(header+body, start)
    assert any(t == "CRYPTO" for _,_,t in frames)
