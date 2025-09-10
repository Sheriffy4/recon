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

class DummyWriter:
    def __init__(self):
        self.sent = []
    def send(self, pkt):
        self.sent.append(("orig", len(getattr(pkt, "payload", b""))))

def test_fakeddisorder_forced_simple_applies_params():
    be = BypassEngine(debug=False)
    be.set_strategy_override({"type": "fakeddisorder", "params": {"split_pos": 76, "overlap_size": 336, "ttl": 2, "fooling": ["badsum","badseq"]}})
    pkt = DummyPacket()
    w = DummyWriter()

    captured = {}
    def fake_send_attack_segments(packet, writer, segs):
        # capture segments and options
        captured["segs"] = segs
        return True

    with patch.object(BPypassEngine if False else BypassEngine, "_send_attack_segments", side_effect=fake_send_attack_segments):
        task = {"type": "fakeddisorder", "params": {"split_pos": 76, "overlap_size": 336, "ttl": 2, "fooling": ["badsum","badseq"], "force_simple": True}}
        be.apply_bypass(pkt, w, task, task["params"], "fakeddisorder", pkt.payload)

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

def test_badsum_race_builds_two_packets():
    be = BypassEngine(debug=False)
    pkt = DummyPacket()
    w = DummyWriter()
    captured = {}
    def fake_send_attack_segments(packet, writer, segs):
        captured["segs"] = segs
        return True
    with patch.object(BypassEngine, "_send_attack_segments", side_effect=fake_send_attack_segments):
        task = {"type": "badsum_race", "params": {"fake_ttl": 1, "real_ttl": 64, "delay_ms": 2}}
        be.apply_bypass(pkt, w, task, task["params"], "badsum_race", pkt.payload)

    segs = captured["segs"]
    assert len(segs) == 2
    fake_opts = segs[0][2]
    real_opts = segs[1][2]
    assert fake_opts.get("is_fake") is True and fake_opts.get("corrupt_tcp_checksum") is True
    assert real_opts.get("ttl") == 64