from types import SimpleNamespace

import pytest


def test_domain_strategy_engine_non_default_strategy_selected_via_extracted_domain(
    monkeypatch, tmp_path
):
    # Use real DomainStrategyEngine, but stub extractor to avoid relying on parser internals
    from core.bypass.engine.domain_strategy_engine import DomainStrategyEngine

    class FakeExtractor:
        def __init__(self, *a, **k):
            pass

        def extract_from_payload(self, payload: bytes | None):
            # emulate tls sni extraction; ensure payload is bytes-like
            assert payload is None or isinstance(payload, (bytes,))
            return SimpleNamespace(domain="video.example.com", source="tls_sni")

    # Ensure our fake extractor is used
    monkeypatch.setattr(
        "core.bypass.engine.domain_strategy_engine.SNIDomainExtractor",
        lambda enable_fast_sni=True: FakeExtractor(),
    )

    # Provide domain_rules_path file (StrategyValidator loads it; can be empty)
    rules_path = tmp_path / "domain_rules.json"
    rules_path.write_text(
        '{"video.example.com": {"type": "fake", "params": {"ttl": 3}}}', encoding="utf-8"
    )

    engine = DomainStrategyEngine(
        domain_rules={"video.example.com": {"type": "fake", "params": {"ttl": 3}}},
        default_strategy={"type": "passthrough", "params": {}},
        enable_ip_resolution=False,
        domain_rules_path=str(rules_path),
    )

    class P:
        dst_addr = "1.2.3.4"
        dst_port = 443
        payload = memoryview(b"\x16\x03\x01\x00\x2a")

    res = engine.get_strategy_for_packet(P())
    assert res.domain == "video.example.com"
    assert res.strategy["type"] == "fake"


def test_strategy_validator_mismatch_is_fail_open(tmp_path):
    from core.bypass.engine.strategy_validator import StrategyValidator

    rules_path = tmp_path / "domain_rules.json"
    rules_path.write_text(
        '{"a.example": {"type": "fake", "params": {"ttl": 3, "split_pos": 5}}}', encoding="utf-8"
    )

    v = StrategyValidator(domain_rules_path=str(rules_path))
    applied = {"type": "fake", "params": {"ttl": 4, "split_pos": 5}}

    r = v.validate_strategy_application(
        domain="a.example", applied_strategy=applied, match_type="exact"
    )
    assert r.valid is True
    assert r.mismatches  # should contain at least ttl mismatch


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
