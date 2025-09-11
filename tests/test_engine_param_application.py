import types
from unittest.mock import patch, MagicMock
from core.bypass_engine import BypassEngine

class DummyPacket:
    def __init__(self, payload=b"A"*200):
        self.payload = payload
        self.src_addr = "1.1.1.1"
        self.dst_addr = "2.2.2.2"
        self.src_port = 50000
        self.dst_port = 443
        self.protocol = 6  # TCP
        # Minimal fake IP/TCP header for BypassEngine to read TTL, etc.
        ip_header = b'\x45\x00\x00\x34\x00\x01\x00\x00\x40\x06\x7c\xb0\x01\x01\x01\x01\x02\x02\x02\x02'
        tcp_header = b'\xc3\x50\x00\x2b\x00\x00\x00\x01\x00\x00\x00\x02\x50\x18\x72\x10\xe5\xd8\x00\x00'
        self.raw = ip_header + tcp_header + self.payload
        self.interface = (0, 0)
        self.direction = 0  # OUTBOUND

class DummyWriter:
    def __init__(self):
        self.sent = []
    def send(self, pkt):
        self.sent.append(("orig", len(getattr(pkt, "payload", b""))))

def test_fakeddisorder_applies_params():
    """
    Tests that apply_bypass correctly processes a technique from the registry
    and passes the resulting segments to the sender.
    """
    with patch("platform.system", return_value="Windows"):
        be = BypassEngine(debug=False)
        win_engine = be._engine

    pkt = DummyPacket()
    w = DummyWriter()

    # We patch _send_attack_segments on the actual engine instance
    win_engine._send_attack_segments = MagicMock(return_value=True)

    task = {"type": "fakeddisorder", "params": {"split_pos": 76, "overlap_size": 336, "fooling": ["badsum","badseq"]}}
    win_engine.apply_bypass(pkt, w, task)

    # Check that _send_attack_segments was called
    win_engine._send_attack_segments.assert_called_once()

    # Inspect the segments passed to the sender
    call_args = win_engine._send_attack_segments.call_args
    sent_segs = call_args[0][2] # packet, writer, segments

    assert len(sent_segs) == 2
    right, left = sent_segs[0], sent_segs[1]

    # Check the segments content based on FakeddisorderTechnique logic
    payload = pkt.payload
    right_payload = payload[76:]
    left_payload = payload[:76]

    assert right[0] == right_payload
    assert right[1] == 76

    assert left[0] == left_payload
    assert left[1] == 76 - 336

    # Check options on the fake segment
    opts1 = right[2]
    assert opts1.get("is_fake") is True
    assert opts1.get("corrupt_tcp_checksum") is True
    assert opts1.get("corrupt_sequence") is True