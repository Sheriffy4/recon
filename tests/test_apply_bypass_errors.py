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
    def __init__(self, behavior):
        """
        behavior:
          - list recipe: return that recipe
          - callable: called to produce recipe or raise
        """
        self.behavior = behavior
        self.calls = []

    def dispatch_attack(self, task_type, dispatch_params, payload, packet_info):
        self.calls.append((task_type, dispatch_params, payload, packet_info))
        if callable(self.behavior):
            return self.behavior()
        return self.behavior


class DummyPacketSender:
    def __init__(self, ok=True, raise_exc: Exception | None = None):
        self.ok = ok
        self.raise_exc = raise_exc
        self.context = None

    def set_strategy_context(self, **kwargs):
        self.context = dict(kwargs)

    def send_tcp_segments(self, w, packet, specs):
        if self.raise_exc:
            raise self.raise_exc
        return self.ok


@pytest.fixture
def engine():
    from core.bypass.engine.base_engine import WindowsBypassEngine

    e = WindowsBypassEngine.__new__(WindowsBypassEngine)
    e.debug = False
    e.logger = logging.getLogger("test.apply_bypass.errors")
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

    # helpers used by apply_bypass
    e._log_rate_limited = lambda *a, **k: None
    e._validate_strategy_before_application = lambda packet_info, strategy: True
    e._resolve_domain_for_strategy_context = lambda *a, **k: None
    e._generate_multisplit_positions = lambda split_pos, split_count: [int(split_pos)] * int(
        split_count
    )
    e.calculate_autottl = lambda dst_ip, offset: 64
    e._update_success_metrics = lambda: None
    e._create_strategy_failure_diagnostic_report = lambda **kw: None

    # metrics capture
    reasons = []
    e._update_fallback_metrics = lambda reason: reasons.append(reason)
    e._fallback_reasons = reasons

    return e


def test_validation_failed_forwards_original_no_metrics(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=1, payload=b"abc")
    engine._validate_strategy_before_application = lambda *_a, **_k: False

    engine.apply_bypass(p, w, {"type": "fake", "params": {}}, forced=True, strategy_result=None)

    assert len(w.sent) == 1
    assert engine._fallback_reasons == []  # old semantics: no _update_fallback_metrics here


def test_dispatch_value_error_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=2, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher(
        lambda: (_ for _ in ()).throw(ValueError("bad params"))
    )
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["validation_error"]


def test_dispatch_exception_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=3, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher(
        lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["dispatch_error"]


def test_empty_recipe_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=4, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["empty_recipe"]


def test_spec_conversion_exception_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=5, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: (_ for _ in ()).throw(
        Exception("spec fail")
    )
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["spec_conversion_exception"]


def test_spec_conversion_failure_empty_specs_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=6, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: []
    engine._packet_sender = DummyPacketSender(ok=True)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["spec_conversion_failure"]


def test_packet_sender_exception_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=7, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=True, raise_exc=RuntimeError("send fail"))

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["packet_sending_exception"]


def test_packet_sender_returns_false_forwards_original_with_reason(engine):
    w = DummyWinDivert()
    p = DummyPacket(seq=8, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=False)

    engine.apply_bypass(
        p, w, {"type": "fake", "params": {"ttl": 3}}, forced=True, strategy_result=None
    )

    assert len(w.sent) == 1
    assert engine._fallback_reasons == ["packet_sending_failure"]


def test_combo_task_type_path_is_exercised(engine):
    # Not a full combo execution (we stub everything), but ensures _resolve_task_type is stable in apply_bypass.
    w = DummyWinDivert()
    p = DummyPacket(seq=9, payload=b"abc")
    engine._attack_dispatcher = DummyAttackDispatcher([(b"a", 0, {"ttl": 64})])
    engine._recipe_to_specs = lambda recipe, payload, strategy_task: ["SPEC"]
    engine._packet_sender = DummyPacketSender(ok=True)

    strategy = {"type": "fakeddisorder", "params": {"ttl": 3}, "attacks": ["fake", "disorder"]}
    engine.apply_bypass(p, w, strategy, forced=True, strategy_result=None)
    assert len(w.sent) == 0  # success => original dropped


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
