import logging
import struct
import threading

import pytest


class DummyWinDivert:
    def __init__(self):
        self.sent = []

    def send(self, pkt, *args, **kwargs):
        self.sent.append(pkt)


class DummyTCP:
    def __init__(self, seq: int, flags: int):
        raw = bytearray(20)
        raw[4:8] = struct.pack("!I", seq)
        raw[13] = flags & 0xFF
        self.raw = bytes(raw)


class DummyPacket:
    def __init__(self, seq: int = 1, flags: int = 0x18, payload: bytes = b"x"):
        self.src_addr = "10.0.0.1"
        self.dst_addr = "20.0.0.1"
        self.src_port = 12345
        self.dst_port = 443
        self.payload = payload
        self.tcp = DummyTCP(seq=seq, flags=flags)


class DummyProcessedCache:
    def __init__(self):
        self.processed = set()
        self.removed = []

    def remove_flow(self, flow_key):
        self.removed.append(flow_key)

    def is_processed(self, flow_key, seq):
        return (flow_key, seq) in self.processed

    def mark_processed(self, flow_key, seq):
        self.processed.add((flow_key, seq))


class DummyAttackDispatcher:
    def __init__(self, recipe):
        self.recipe = recipe
        self.calls = []

    def dispatch_attack(self, task_type, dispatch_params, payload, packet_info):
        self.calls.append((task_type, dispatch_params, payload, packet_info))
        return self.recipe


class DummyPacketSender:
    def __init__(self, ok=True):
        self.ok = ok
        self.context = None
        self.sent_specs = None

    def set_strategy_context(self, **kwargs):
        self.context = dict(kwargs)

    def send_tcp_segments(self, w, packet, specs):
        self.sent_specs = specs
        return self.ok


@pytest.fixture
def engine():
    # Create WindowsBypassEngine without calling __init__
    from core.bypass.engine.base_engine import WindowsBypassEngine

    e = WindowsBypassEngine.__new__(WindowsBypassEngine)
    e.debug = False
    e.logger = logging.getLogger("test.apply_bypass")
    e.logger.addHandler(logging.NullHandler())

    e._processed_packet_cache = DummyProcessedCache()
    e._inject_sema = threading.Semaphore(1)
    e._lock = threading.Lock()
    e._tlock = threading.Lock()
    e._processed_flows = {}
    e._flow_timeout = 15.0
    e._retransmission_count = 0
    e._telemetry = {"total_retransmissions_detected": 0}
    e._failed_strategies = {}
    e._strategy_failure_threshold = 3
    e._domain_strategy_engine = None
    e._position_resolver = None
    e._INJECT_MARK = 0xC0DE

    # methods used by apply_bypass
    e._log_rate_limited = lambda *a, **k: None
    e._validate_strategy_before_application = lambda packet_info, strategy: True
    e._resolve_domain_for_strategy_context = lambda *a, **k: None
    e._generate_multisplit_positions = lambda split_pos, split_count: [int(split_pos)] * int(
        split_count
    )
    e.calculate_autottl = lambda dst_ip, offset: 64
    e._update_fallback_metrics = lambda reason: None
    e._update_success_metrics = lambda: None
    e._create_strategy_failure_diagnostic_report = lambda **kw: None

    return e


def test_fin_packet_is_forwarded_and_cache_cleared(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=10, flags=0x01, payload=b"abc")  # FIN
    strategy = {"type": "fake", "params": {}}

    engine.apply_bypass(p, w, strategy, forced=True, strategy_result=None)

    assert len(w.sent) == 1
    assert engine._processed_packet_cache.removed  # flow removed


def test_rst_packet_is_forwarded_and_cache_cleared(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=11, flags=0x04, payload=b"abc")  # RST
    strategy = {"type": "fake", "params": {}}

    engine.apply_bypass(p, w, strategy, forced=True, strategy_result=None)

    assert len(w.sent) == 1
    assert engine._processed_packet_cache.removed


def test_retransmission_is_dropped(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=123, flags=0x18, payload=b"abc")
    flow_key = (p.src_addr, p.src_port, p.dst_addr, p.dst_port)
    engine._processed_packet_cache.mark_processed(flow_key, 123)

    engine.apply_bypass(p, w, {"type": "fake", "params": {}}, forced=True, strategy_result=None)

    assert len(w.sent) == 0  # dropped


def test_retransmission_updates_telemetry_counter(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=200, flags=0x18, payload=b"abc")
    flow_key = (p.src_addr, p.src_port, p.dst_addr, p.dst_port)
    engine._processed_packet_cache.mark_processed(flow_key, 200)

    assert engine._retransmission_count == 0
    assert engine._telemetry.get("total_retransmissions_detected", 0) == 0

    engine.apply_bypass(p, w, {"type": "fake", "params": {}}, forced=True, strategy_result=None)

    assert len(w.sent) == 0
    assert engine._retransmission_count == 1
    assert engine._telemetry.get("total_retransmissions_detected", 0) == 1


def test_semaphore_limit_forwards_original(engine):
    w = DummyWinDivert()
    # take semaphore so acquire(blocking=False) fails
    assert engine._inject_sema.acquire(blocking=False) is True

    p = DummyPacket(seq=1, flags=0x18, payload=b"abc")
    engine.apply_bypass(p, w, {"type": "fake", "params": {}}, forced=True, strategy_result=None)

    assert len(w.sent) == 1


def test_successful_send_marks_processed_and_drops_original(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=55, flags=0x18, payload=b"abc")

    # make recipe -> specs -> sender ok
    engine._attack_dispatcher = DummyAttackDispatcher(recipe=[(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC1"]
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    # original packet must NOT be forwarded on success
    assert len(w.sent) == 0
    flow_key = (p.src_addr, p.src_port, p.dst_addr, p.dst_port)
    assert (flow_key, 55) in engine._processed_packet_cache.processed


def test_send_failure_forwards_original(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=56, flags=0x18, payload=b"abc")

    engine._attack_dispatcher = DummyAttackDispatcher(recipe=[(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC1"]
    engine._packet_sender = DummyPacketSender(ok=False)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1  # forwarded original


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
