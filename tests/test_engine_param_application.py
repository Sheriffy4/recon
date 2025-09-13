import pytest
import platform
import types
from unittest.mock import patch, MagicMock

if platform.system() == "Windows":
    from core.bypass.engine.windows_engine import WindowsBypassEngine
    from core.bypass.engine.base_engine import EngineConfig

class DummyPacket:
    def __init__(self, payload=b"A"*200):
        self.payload = payload
        self.src_addr = "1.1.1.1"
        self.dst_addr = "2.2.2.2"
        self.src_port = 50000
        self.dst_port = 443
        self.protocol = 6  # TCP
        # Minimal fake IP/TCP header for WindowsBypassEngine to read TTL, etc.
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

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
def test_fakeddisorder_forced_simple_applies_params():
    be = WindowsBypassEngine(config=EngineConfig(debug=False))
    be.set_strategy_override({"type": "fakeddisorder", "params": {"split_pos": 76, "overlap_size": 336, "ttl": 2, "fooling": ["badsum","badseq"]}})
    pkt = DummyPacket()
    w = DummyWriter()

    captured = {}
    def fake_send_attack_segments(packet, writer, segs):
        # capture segments and options
        captured["segs"] = segs
        return True

    with patch.object(WindowsBypassEngine, "_send_attack_segments", side_effect=fake_send_attack_segments):
        task = {"type": "fakeddisorder", "params": {"split_pos": 76, "overlap_size": 336, "ttl": 2, "fooling": ["badsum","badseq"], "force_simple": True}}
        be.apply_bypass(pkt, w, task)

    segs = captured["segs"]
    # ожидаем 2 сегмента: сначала right с offset=split_pos, затем left с offset=split_pos-overlap
    assert len(segs) == 2
    right, left = segs[0], segs[1]
    assert right[1] == 76
    assert left[1] == 76 - 336
    # в опциях первого фейкового должны быть флаги badsum/badseq
    opts1 = right[2]
    assert opts1.get("is_fake") is True
    assert opts1.get("corrupt_tcp_checksum") is True
    assert opts1.get("corrupt_sequence") is True

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
def test_badsum_race_sends_fake_then_original():
    be = WindowsBypassEngine(config=EngineConfig(debug=False))
    pkt = DummyPacket()
    w = DummyWriter()

    with patch.object(be, '_send_fake_packet_with_badsum') as mock_send_fake, \
         patch.object(w, 'send') as mock_send_orig:

        task = {"type": "badsum_race", "params": {"fake_ttl": 1}}
        be.apply_bypass(pkt, w, task)

        mock_send_fake.assert_called_once()
        mock_send_orig.assert_called_once_with(pkt)